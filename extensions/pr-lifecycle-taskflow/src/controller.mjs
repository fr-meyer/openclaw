import { createHash } from "node:crypto";

export const CONTROLLER_ID = "pr-lifecycle-taskflow/v1";
export const STATE_SCHEMA_VERSION = 1;
export const REMEDIATOR_PROFILE_SCHEMA_VERSION = 1;
export const MERGE_AUTHORIZATION_SCHEMA_VERSION = 1;
export const TERMINAL_ENVELOPE_SCHEMA_VERSION = 1;

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
export const MAX_PROTOCOL_RETRIES = 1;
export const PRIMARY_FIXER_MODEL = "primary-fixer";
export const FALLBACK_FIXER_MODEL = "fallback-fixer";
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
  return findings.every(
    (finding) => typeof finding?.path === "string" && finding.path.trim().length > 0,
  );
}

export function refreshPolicySnapshot(state, policyInput, now = Date.now(), options = {}) {
  if (!isLifecycleState(state)) {
    throw new Error("stored lifecycle state is invalid");
  }
  const policy = normalizePolicy(policyInput);
  const currentMergePolicyDigest = mergePolicyDigest(policy, state.repo);
  if (
    policy.mergeAuthorization &&
    policy.mergeAuthorization.policyDigest !== currentMergePolicyDigest
  ) {
    throw new Error("mergeAuthorization.policyDigest does not match repository policy");
  }
  const resetDeadline = options.resetDeadline === true;
  const adoptExecutionPolicy = options.adoptExecutionPolicy === true || resetDeadline;
  const proposedDeadline = now + policy.wallTimeMinutes * 60_000;
  const deadlineAt = resetDeadline
    ? proposedDeadline
    : Number.isFinite(state.deadlineAt)
      ? Math.min(state.deadlineAt, proposedDeadline)
      : proposedDeadline;
  const publisherBoundary = publisherBoundaryFromPolicy(policy);
  const remediatorProfile = adoptExecutionPolicy
    ? policy.remediatorProfile
    : (state.remediatorProfile ?? null);
  const mergeAuthorization = adoptExecutionPolicy
    ? policy.mergeAuthorization
    : (state.mergeAuthorization ?? null);
  const next = {
    ...state,
    mode: policy.mode,
    reviewActor: policy.reviewActor,
    authorActor: policy.authorActor,
    fixerModel: policy.fixerModel,
    fixerFallbackModel: policy.fixerFallbackModel,
    publisherBoundary,
    remediatorProfile,
    remediatorProfileDigest: remediatorProfile?.digest ?? null,
    configuredRemediatorProfileDigest: policy.remediatorProfile?.digest ?? null,
    mergeAuthorization,
    configuredMergeAuthorizationDigest: policy.mergeAuthorization?.digest ?? null,
    mergePolicyDigest: currentMergePolicyDigest,
    brokerRepoAlias: policy.brokerRepoAlias,
    autoMergeBaseBranches: policy.autoMergeBaseBranches,
    autoMergeMethod: policy.autoMergeMethod,
    maxCycles: policy.maxCycles,
    maxRetries: policy.maxRetries,
    wallTimeMinutes: policy.wallTimeMinutes,
    deadlineAt,
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
    next.remediatorProfileDigest !== (state.remediatorProfileDigest ?? null) ||
    next.configuredRemediatorProfileDigest !==
      (state.configuredRemediatorProfileDigest ?? state.remediatorProfileDigest ?? null) ||
    next.mergeAuthorization?.digest !== state.mergeAuthorization?.digest ||
    next.configuredMergeAuthorizationDigest !==
      (state.configuredMergeAuthorizationDigest ?? state.mergeAuthorization?.digest ?? null) ||
    next.mergePolicyDigest !== state.mergePolicyDigest ||
    next.brokerRepoAlias !== state.brokerRepoAlias ||
    JSON.stringify(next.autoMergeBaseBranches) !== JSON.stringify(state.autoMergeBaseBranches) ||
    next.autoMergeMethod !== state.autoMergeMethod ||
    next.maxCycles !== state.maxCycles ||
    next.maxRetries !== state.maxRetries ||
    next.wallTimeMinutes !== state.wallTimeMinutes ||
    next.deadlineAt !== state.deadlineAt ||
    next.cycleStartedAt !== state.cycleStartedAt;
  return { changed, state: changed ? next : state };
}

const TERMINAL_PHASES = new Set([PHASE.MERGED, PHASE.FAILED, PHASE.CANCELLED]);
const SHA_PATTERN = /^[0-9a-f]{40}$/;
const REPO_PATTERN = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
const SAFE_TEXT_PATTERN = /^[^\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]*$/;
const MAX_SEEN_EVENTS = 64;
const MAX_FINDINGS = 20;
const MAX_TERMINAL_ENVELOPES = 8;

function canonicalJson(value) {
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalJson(item)).join(",")}]`;
  }
  if (value && typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function digestObject(value) {
  return createHash("sha256").update(canonicalJson(value)).digest("hex");
}

function cleanRelativePath(value, field) {
  const path = cleanText(value, 500, field);
  const normalized = path.endsWith("/") ? path.slice(0, -1) : path;
  const components = normalized.split("/");
  if (
    !normalized ||
    path.startsWith("/") ||
    path.includes("\\") ||
    components.some((component) => component === "" || component === "." || component === "..")
  ) {
    throw new Error(`${field} must be a repository-relative path`);
  }
  return path;
}

function cleanAbsolutePath(value, field) {
  const path = cleanText(value, 1000, field);
  const components = path.slice(1).split("/");
  if (
    path === "/" ||
    !path.startsWith("/") ||
    path.endsWith("/") ||
    path.includes("\\") ||
    components.some((component) => component === "" || component === "." || component === "..")
  ) {
    throw new Error(`${field} must be a normalized absolute path`);
  }
  return path;
}

function normalizeUniqueStrings(value, field, maxItems, mapper) {
  if (!Array.isArray(value) || value.length === 0 || value.length > maxItems) {
    throw new Error(`${field} must be a non-empty array with at most ${maxItems} entries`);
  }
  return [...new Set(value.map((item, index) => mapper(item, `${field}[${index}]`)))];
}

function normalizeStrings(value, field, maxItems, mapper) {
  if (!Array.isArray(value) || value.length === 0 || value.length > maxItems) {
    throw new Error(`${field} must be a non-empty array with at most ${maxItems} entries`);
  }
  return value.map((item, index) => mapper(item, `${field}[${index}]`));
}

export function normalizeRemediatorProfile(input) {
  if (input === undefined || input === null) {
    return null;
  }
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    throw new Error("remediatorProfile must be an object");
  }
  if (input.schemaVersion !== REMEDIATOR_PROFILE_SCHEMA_VERSION) {
    throw new Error(`remediatorProfile.schemaVersion must be ${REMEDIATOR_PROFILE_SCHEMA_VERSION}`);
  }
  const repository = cleanText(input.repository, 200, "remediatorProfile.repository");
  if (!isRepo(repository)) {
    throw new Error("remediatorProfile.repository is invalid");
  }
  const seedWorkspace = cleanAbsolutePath(input.seedWorkspace, "remediatorProfile.seedWorkspace");
  const worktreeRoot = cleanAbsolutePath(input.worktreeRoot, "remediatorProfile.worktreeRoot");
  const baseBranches = normalizeUniqueStrings(
    input.baseBranches,
    "remediatorProfile.baseBranches",
    16,
    (item, field) => cleanText(item, 200, field),
  );
  const pullRequests = normalizeUniqueStrings(
    input.pullRequests,
    "remediatorProfile.pullRequests",
    64,
    (item, field) => positiveInteger(item, field),
  );
  const headBranchPattern = cleanText(
    input.headBranchPattern,
    500,
    "remediatorProfile.headBranchPattern",
  );
  try {
    new RegExp(headBranchPattern);
  } catch {
    throw new Error("remediatorProfile.headBranchPattern is invalid");
  }
  const allowedWritePaths = normalizeUniqueStrings(
    input.allowedWritePaths,
    "remediatorProfile.allowedWritePaths",
    128,
    cleanRelativePath,
  );
  const requiredTestPaths = normalizeUniqueStrings(
    input.requiredTestPaths,
    "remediatorProfile.requiredTestPaths",
    64,
    cleanRelativePath,
  );
  if (!Array.isArray(input.validationCommands) || input.validationCommands.length === 0) {
    throw new Error("remediatorProfile.validationCommands must be a non-empty array");
  }
  if (input.validationCommands.length > 32) {
    throw new Error("remediatorProfile.validationCommands has too many entries");
  }
  const validationCommands = input.validationCommands.map((command, index) => {
    if (!command || typeof command !== "object" || Array.isArray(command)) {
      throw new Error(`remediatorProfile.validationCommands[${index}] must be an object`);
    }
    const argv = normalizeStrings(
      command.argv,
      `remediatorProfile.validationCommands[${index}].argv`,
      64,
      (item, field) => cleanText(item, 500, field),
    );
    const covers = normalizeUniqueStrings(
      command.covers,
      `remediatorProfile.validationCommands[${index}].covers`,
      64,
      cleanRelativePath,
    );
    const timeoutSeconds = command.timeoutSeconds ?? 1800;
    if (!Number.isInteger(timeoutSeconds) || timeoutSeconds < 1 || timeoutSeconds > 3600) {
      throw new Error(`remediatorProfile.validationCommands[${index}].timeoutSeconds is invalid`);
    }
    return { argv, covers, timeoutSeconds };
  });
  const covered = new Set(validationCommands.flatMap((command) => command.covers));
  if (requiredTestPaths.some((path) => !covered.has(path))) {
    throw new Error("remediatorProfile required test-path coverage is incomplete");
  }
  const publicationMode = cleanText(input.publicationMode, 80, "remediatorProfile.publicationMode");
  const publicationRoute = cleanText(
    input.publicationRoute,
    80,
    "remediatorProfile.publicationRoute",
  );
  const commitSubject = cleanText(input.commitSubject, 200, "remediatorProfile.commitSubject");
  const attestationPolicy = cleanText(
    input.attestationPolicy,
    80,
    "remediatorProfile.attestationPolicy",
  );
  if (
    publicationMode !== "attested-broker" ||
    !new Set(["exact-lease", "workspace-bridge"]).has(publicationRoute) ||
    attestationPolicy !== "required"
  ) {
    throw new Error("remediatorProfile publication or attestation policy is invalid");
  }
  const normalized = {
    schemaVersion: REMEDIATOR_PROFILE_SCHEMA_VERSION,
    repository,
    pullRequests,
    headBranchPattern,
    baseBranches,
    seedWorkspace,
    worktreeRoot,
    allowedWritePaths,
    requiredTestPaths,
    validationCommands,
    publicationMode,
    publicationRoute,
    commitSubject,
    attestationPolicy,
  };
  return { ...normalized, digest: digestObject(normalized) };
}

export function mergePolicyDigest(policy, repository) {
  if (!policy || typeof policy !== "object" || !isRepo(repository)) {
    throw new Error("merge policy digest input is invalid");
  }
  return digestObject({
    schemaVersion: 1,
    repository,
    brokerRepoAlias: policy.brokerRepoAlias,
    baseBranches: policy.baseBranches,
    autoMergeBaseBranches: policy.autoMergeBaseBranches,
    autoMergeMethod: policy.autoMergeMethod,
    mergeActor: policy.mergeActor ?? null,
    reviewActor: policy.reviewActor,
    authorActor: policy.authorActor,
    publisherBrokerId: policy.publisherBrokerId ?? null,
    publisherAttestationRef: policy.publisherAttestationRef ?? null,
    remediatorProfileDigest: policy.remediatorProfile?.digest ?? null,
    maxCycles: policy.maxCycles,
    maxRetries: policy.maxRetries,
    wallTimeMinutes: policy.wallTimeMinutes,
    allowForks: policy.allowForks === true,
  });
}

export function normalizeMergeAuthorization(input) {
  if (input === undefined || input === null) {
    return null;
  }
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    throw new Error("mergeAuthorization must be an object");
  }
  if (input.schemaVersion !== MERGE_AUTHORIZATION_SCHEMA_VERSION) {
    throw new Error(
      `mergeAuthorization.schemaVersion must be ${MERGE_AUTHORIZATION_SCHEMA_VERSION}`,
    );
  }
  const repository = cleanText(input.repository, 200, "mergeAuthorization.repository");
  if (!isRepo(repository)) {
    throw new Error("mergeAuthorization.repository is invalid");
  }
  const authorizedAt = input.authorizedAt;
  const expiresAt = input.expiresAt;
  if (
    !Number.isInteger(authorizedAt) ||
    !Number.isInteger(expiresAt) ||
    authorizedAt < 1 ||
    expiresAt <= authorizedAt
  ) {
    throw new Error("mergeAuthorization time bounds are invalid");
  }
  const baseRef = cleanText(input.baseRef, 200, "mergeAuthorization.baseRef");
  const mergeMethod = cleanText(input.mergeMethod, 20, "mergeAuthorization.mergeMethod");
  if (mergeMethod !== "merge") {
    throw new Error("mergeAuthorization.mergeMethod must be merge");
  }
  const policyDigest = cleanText(input.policyDigest, 64, "mergeAuthorization.policyDigest");
  if (!/^[0-9a-f]{64}$/.test(policyDigest)) {
    throw new Error("mergeAuthorization.policyDigest is invalid");
  }
  const normalized = {
    schemaVersion: MERGE_AUTHORIZATION_SCHEMA_VERSION,
    authorizationId: cleanText(input.authorizationId, 160, "mergeAuthorization.authorizationId"),
    authorizer: cleanText(input.authorizer, 200, "mergeAuthorization.authorizer"),
    authorizedAt,
    expiresAt,
    repository,
    prNumber: positiveInteger(input.prNumber, "mergeAuthorization.prNumber"),
    baseRef,
    mergeMethod,
    sourceRef: cleanText(input.sourceRef, 500, "mergeAuthorization.sourceRef"),
    policyVersion: cleanText(input.policyVersion, 80, "mergeAuthorization.policyVersion"),
    policyDigest,
    revokedAt:
      input.revokedAt === undefined || input.revokedAt === null
        ? null
        : positiveInteger(input.revokedAt, "mergeAuthorization.revokedAt"),
    supersededBy:
      input.supersededBy === undefined || input.supersededBy === null
        ? null
        : cleanText(input.supersededBy, 160, "mergeAuthorization.supersededBy"),
  };
  return { ...normalized, digest: digestObject(normalized) };
}

export function mergeAuthorizationAllows(state, now = Date.now()) {
  const authorization = state?.mergeAuthorization;
  return Boolean(
    authorization &&
    authorization.schemaVersion === MERGE_AUTHORIZATION_SCHEMA_VERSION &&
    authorization.repository === state.repo &&
    authorization.prNumber === state.prNumber &&
    authorization.baseRef === state.baseRef &&
    authorization.mergeMethod === (state.autoMergeMethod ?? "merge") &&
    authorization.policyDigest === state.mergePolicyDigest &&
    authorization.revokedAt === null &&
    authorization.supersededBy === null &&
    authorization.authorizedAt <= now &&
    authorization.expiresAt > now,
  );
}

export function authorizeMergeReady(state, policyInput, now = Date.now()) {
  if (!isLifecycleState(state)) {
    throw new Error("stored lifecycle state is invalid");
  }
  if (state.phase !== PHASE.MERGE_READY) {
    return { changed: false, state, effect: "none", reason: "merge_ready_required" };
  }
  const exactReviewReady =
    state.review?.outcome === "approved" &&
    state.review?.coverageComplete === true &&
    state.review?.findingsCount === 0 &&
    state.review?.headSha === state.headSha &&
    state.mergeReady?.headSha === state.headSha &&
    state.mergeReady?.reviewId === state.review?.reviewId &&
    state.mergeReady?.coverageComplete === true &&
    state.mergeReady?.findingsCount === 0 &&
    state.mergeReady?.mergeAuthorized !== true &&
    Array.isArray(state.findings) &&
    state.findings.length === 0;
  if (!exactReviewReady) {
    return { changed: false, state, effect: "none", reason: "merge_ready_evidence_invalid" };
  }
  const refreshed = refreshPolicySnapshot(state, policyInput, now, {
    adoptExecutionPolicy: true,
  }).state;
  const authorizationReady =
    refreshed.mode === "active" &&
    refreshed.autoMergeMethod === "merge" &&
    Array.isArray(refreshed.autoMergeBaseBranches) &&
    refreshed.autoMergeBaseBranches.includes(refreshed.baseRef) &&
    mergeAuthorizationAllows(refreshed, now);
  if (!authorizationReady) {
    return { changed: false, state, effect: "none", reason: "merge_authorization_not_ready" };
  }
  return {
    changed: true,
    state: {
      ...refreshed,
      phase: PHASE.MERGE_QUEUED,
      mergeReady: {
        ...refreshed.mergeReady,
        mergeAuthorized: true,
        mergeMethod: refreshed.autoMergeMethod ?? "merge",
        authorizationDigest: refreshed.mergeAuthorization.digest,
        authorizationAdoptedAt: now,
      },
      wait: null,
      blocker: null,
      updatedAt: now,
    },
    effect: "continue",
    reason: "owner_authorized_merge_queued",
  };
}

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

function cleanRepositoryRelativePath(value, field) {
  const cleaned = cleanText(value, 300, field);
  if (
    cleaned.startsWith("/") ||
    cleaned.startsWith("\\") ||
    /^[A-Za-z]:[\\/]/.test(cleaned) ||
    cleaned.includes("\\") ||
    cleaned.split("/").some((segment) => !segment || segment === "." || segment === "..")
  ) {
    throw new Error(`${field} must be a normalized repository-relative path`);
  }
  return cleaned;
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

function optionalGithubUpdatedAt(value, field) {
  if (value === undefined || value === null || value === "") {
    return null;
  }
  const text = cleanText(value, 40, field);
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/.test(text)) {
    throw new Error(`${field} must be an ISO-8601 UTC timestamp`);
  }
  const timestamp = Date.parse(text);
  if (!Number.isSafeInteger(timestamp)) {
    throw new Error(`${field} must be a valid timestamp`);
  }
  return timestamp;
}

function githubNumericId(value, field) {
  const text = Number.isSafeInteger(value) ? String(value) : value;
  if (typeof text !== "string" || !/^[1-9]\d{0,39}$/.test(text)) {
    throw new Error(`${field} must be a positive GitHub numeric identifier`);
  }
  return text;
}

function compareGithubNumericIds(left, right) {
  const normalizedLeft = left.replace(/^0+/, "") || "0";
  const normalizedRight = right.replace(/^0+/, "") || "0";
  if (normalizedLeft.length !== normalizedRight.length) {
    return normalizedLeft.length < normalizedRight.length ? -1 : 1;
  }
  return normalizedLeft === normalizedRight ? 0 : normalizedLeft < normalizedRight ? -1 : 1;
}

function staleCheckSuiteEvent(wait, event) {
  if (!wait || wait.kind !== "check_suite") {
    return false;
  }
  if (typeof wait.suiteId !== "string" || !Number.isSafeInteger(wait.githubUpdatedAt)) {
    if (wait.origin === "gate_snapshot") {
      return false;
    }
    return event.action === "completed";
  }
  const idOrder = compareGithubNumericIds(event.suiteId, wait.suiteId);
  if (idOrder < 0 || event.githubUpdatedAt < wait.githubUpdatedAt) {
    return true;
  }
  return (
    event.action === "completed" &&
    idOrder === 0 &&
    event.githubUpdatedAt === wait.githubUpdatedAt &&
    !["requested", "rerequested"].includes(wait.action)
  );
}

function maxGithubUpdatedAt(state, event) {
  if (
    Number.isSafeInteger(event.githubUpdatedAt) &&
    (!Number.isSafeInteger(state.githubUpdatedAt) || event.githubUpdatedAt > state.githubUpdatedAt)
  ) {
    return event.githubUpdatedAt;
  }
  return state.githubUpdatedAt ?? null;
}

function recordExternalMilestone(state, milestone) {
  const previous = state.latestExternalMilestone;
  const history = [
    ...(Array.isArray(state.externalMilestoneHistory) ? state.externalMilestoneHistory : []),
    ...(previous ? [previous] : []),
  ].slice(-16);
  return {
    ...state,
    prEffects: milestone.kind,
    latestExternalMilestone: milestone,
    externalMilestoneHistory: history,
  };
}

function reviewMilestone(state, result, now) {
  const reviewId = result.reviewId ?? null;
  if (!reviewId) {
    return null;
  }
  return {
    kind: "review_published",
    headSha: state.headSha,
    observedAt: now,
    observedRevision: null,
    url: `https://github.com/${state.repo}/pull/${state.prNumber}#pullrequestreview-${reviewId}`,
    receipt: { reviewId },
  };
}

function terminalOutcomeClass(outcome) {
  if (
    new Set([
      "waiting_review",
      "approved",
      "changes_requested",
      "fixed_and_published",
      "re_review_same_head",
    ]).has(outcome)
  ) {
    return "success";
  }
  if (outcome === "ambiguous_publication") {
    return "publication_failure";
  }
  if (outcome.includes("preflight")) {
    return "preflight_failure";
  }
  if (outcome.includes("policy")) {
    return "policy_rejection";
  }
  if (outcome.includes("test") || outcome.includes("validation")) {
    return "test_failure";
  }
  return "execution_failure";
}

function terminalEnvelope(state, worker, report, now, overrides = {}) {
  return {
    schemaVersion: TERMINAL_ENVELOPE_SCHEMA_VERSION,
    outcomeClass:
      overrides.outcomeClass ?? report.outcomeClass ?? terminalOutcomeClass(report.outcome),
    jobId: worker.remediationJob?.jobId ?? worker.runId ?? worker.sessionKey,
    flowId: worker.flowId ?? state.flowId ?? null,
    workerSessionKey: worker.sessionKey,
    workerRunId: worker.runId ?? null,
    workerTaskId: worker.taskId ?? null,
    repository: state.repo,
    prNumber: state.prNumber,
    headSha: state.headSha,
    cycle: state.cycle,
    profileDigest: worker.profileDigest ?? state.remediatorProfileDigest ?? null,
    finalStage: overrides.finalStage ?? report.finalStage ?? `${worker.kind}_report`,
    outcome: report.outcome,
    summary: report.summary ?? null,
    publicationAttestation: report.fixerAttestationRef ?? null,
    recordedAt: now,
  };
}

function recordTerminalEnvelope(state, envelope) {
  const history = [
    ...(Array.isArray(state.terminalEnvelopeHistory) ? state.terminalEnvelopeHistory : []),
    ...(state.lastTerminalEnvelope ? [state.lastTerminalEnvelope] : []),
  ].slice(-MAX_TERMINAL_ENVELOPES);
  return { ...state, lastTerminalEnvelope: envelope, terminalEnvelopeHistory: history };
}

function supersedeExternalMilestone(state, now) {
  const previous = state.latestExternalMilestone;
  return {
    ...state,
    prEffects: "none",
    latestExternalMilestone: null,
    externalMilestoneHistory: [
      ...(Array.isArray(state.externalMilestoneHistory) ? state.externalMilestoneHistory : []),
      ...(previous ? [{ ...previous, supersededAt: now }] : []),
    ].slice(-16),
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
    const pathSupplied = ![undefined, null, ""].includes(finding.path);
    return {
      id: cleanText(finding.id, 100, `findings[${index}].id`),
      severity,
      summary: cleanText(finding.summary, 500, `findings[${index}].summary`),
      ...(pathSupplied
        ? { path: cleanRepositoryRelativePath(finding.path, `findings[${index}].path`) }
        : {}),
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
  const fixerFallbackModel = cleanText(
    input.fixerFallbackModel ?? FALLBACK_FIXER_MODEL,
    100,
    "fixerFallbackModel",
  );
  if (fixerModel.toLowerCase() === fixerFallbackModel.toLowerCase()) {
    throw new Error("fixerModel and fixerFallbackModel must be distinct");
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
  const brokerRepoAlias = cleanText(input.brokerRepoAlias, 80, "brokerRepoAlias");
  if (!/^[A-Za-z0-9_.-]+$/.test(brokerRepoAlias)) {
    throw new Error("brokerRepoAlias is invalid");
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
  if (normalizedAutoMergeBaseBranches.some((value) => !baseBranches.includes(value))) {
    throw new Error("autoMergeBaseBranches must be a subset of baseBranches");
  }
  const autoMergeMethod = input.autoMergeMethod ?? "merge";
  if (autoMergeMethod !== "merge") {
    throw new Error("autoMergeMethod must be merge");
  }
  const mergeActor = optionalCleanText(input.mergeActor, 200, "mergeActor");
  if (normalizedAutoMergeBaseBranches.length > 0 && !mergeActor) {
    throw new Error("mergeActor is required when automatic merge is enabled");
  }
  const maxCycles = input.maxCycles ?? 2;
  const maxRetries = input.maxRetries ?? 2;
  const wallTimeMinutes = input.wallTimeMinutes ?? 72 * 60;
  if (!Number.isInteger(maxCycles) || maxCycles < 1 || maxCycles > 2) {
    throw new Error("maxCycles must be an integer between 1 and 2");
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
  const workspace = cleanAbsolutePath(input.workspace, "workspace");
  const remediatorProfile = normalizeRemediatorProfile(input.remediatorProfile);
  const mergeAuthorization = normalizeMergeAuthorization(input.mergeAuthorization);
  return {
    enabled: input.enabled !== false,
    mode,
    workspace,
    brokerRepoAlias,
    baseBranches,
    autoMergeBaseBranches: normalizedAutoMergeBaseBranches,
    autoMergeMethod,
    mergeActor,
    reviewActor,
    authorActor,
    reviewWorkerAgentId,
    authorWorkerAgentId,
    fixerModel,
    fixerFallbackModel,
    publisherBrokerId,
    publisherAttestationRef,
    remediatorProfile,
    mergeAuthorization,
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
  if (!new Set(["opened", "reopened", "synchronize"]).has(action)) {
    throw new Error("pull request action is not handled");
  }
  const repo = cleanText(input.repo, 200, "repo");
  if (!isRepo(repo)) {
    throw new Error("repo is invalid");
  }
  const eventId = cleanText(input.eventId, 160, "eventId");
  const githubUpdatedAt = optionalGithubUpdatedAt(input.updatedAt, "updatedAt");
  if (eventId.startsWith("github:") && githubUpdatedAt === null) {
    throw new Error("GitHub pull-request event requires updatedAt ordering evidence");
  }
  const headSha = cleanText(input.headSha, 40, "headSha").toLowerCase();
  const baseSha = cleanText(input.baseSha, 40, "baseSha").toLowerCase();
  if (!isSha(headSha) || !isSha(baseSha)) {
    throw new Error("headSha and baseSha must be full lowercase commit SHAs");
  }
  return {
    type: "pull_request",
    eventId,
    action,
    repo,
    prNumber: positiveInteger(input.prNumber, "prNumber"),
    headSha,
    baseSha,
    baseRef: cleanText(input.baseRef, 200, "baseRef"),
    headRepo: cleanText(input.headRepo, 200, "headRepo"),
    headRef: optionalCleanText(input.headRef, 500, "headRef") ?? null,
    githubUpdatedAt,
    authoritative: input.authoritative === true,
  };
}

export function normalizeCheckSuiteEvent(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    throw new Error("check suite event must be an object");
  }
  const repo = cleanText(input.repo, 200, "repo");
  const headSha = cleanText(input.headSha, 40, "headSha").toLowerCase();
  if (!isRepo(repo) || !isSha(headSha)) {
    throw new Error("check suite repo or headSha is invalid");
  }
  const action = cleanText(input.action, 40, "action");
  if (!new Set(["completed", "requested", "rerequested"]).has(action)) {
    throw new Error("check suite action is not handled");
  }
  const eventId = cleanText(input.eventId, 160, "eventId");
  const githubUpdatedAt = Number.isSafeInteger(input.githubUpdatedAt)
    ? input.githubUpdatedAt
    : optionalGithubUpdatedAt(input.updatedAt, "updatedAt");
  if (githubUpdatedAt === null) {
    throw new Error("check-suite event requires updatedAt ordering evidence");
  }
  return {
    type: "check_suite",
    eventId,
    action,
    repo,
    prNumber: positiveInteger(input.prNumber, "prNumber"),
    headSha,
    suiteId: githubNumericId(input.suiteId, "suiteId"),
    githubUpdatedAt,
    url: optionalCleanText(input.url, 1000, "url") ?? null,
  };
}

export function applyCheckSuiteEvent(state, eventInput, now = Date.now()) {
  if (!isLifecycleState(state)) {
    throw new Error("stored lifecycle state is invalid");
  }
  const event = normalizeCheckSuiteEvent(eventInput);
  if (event.repo !== state.repo || event.prNumber !== state.prNumber) {
    throw new Error("check suite event does not match this flow");
  }
  if (state.seenEventIds.includes(event.eventId)) {
    return { changed: false, state, effect: "none", reason: "duplicate_event" };
  }
  if (event.headSha !== state.headSha) {
    return { changed: false, state, effect: "none", reason: "stale_head_result" };
  }
  const currentWait = state.phase === PHASE.MERGE_QUEUED ? state.wait : null;
  if (staleCheckSuiteEvent(currentWait, event)) {
    return {
      changed: true,
      state: appendSeenEvent({ ...state, updatedAt: now }, event.eventId),
      effect: "none",
      reason: "stale_check_suite_event",
    };
  }
  const completedForQueuedMerge =
    state.phase === PHASE.MERGE_QUEUED && event.action === "completed";
  const next = appendSeenEvent(
    {
      ...state,
      wait: completedForQueuedMerge
        ? null
        : state.phase === PHASE.MERGE_QUEUED
          ? {
              kind: "check_suite",
              origin: "github_event",
              since: now,
              headSha: state.headSha,
              action: event.action,
              suiteId: event.suiteId,
              githubUpdatedAt: event.githubUpdatedAt,
              url: event.url,
            }
          : state.wait,
      updatedAt: now,
    },
    event.eventId,
  );
  return {
    changed: true,
    state: next,
    effect: completedForQueuedMerge ? "continue" : "none",
    reason: completedForQueuedMerge
      ? "check_suite_reconcile"
      : state.phase === PHASE.MERGE_QUEUED
        ? "check_suite_pending"
        : "check_suite_recorded",
  };
}

export function normalizeReviewResult(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    throw new Error("review result must be an object");
  }
  const repo = cleanText(input.repo, 200, "repo");
  const headSha = cleanText(input.headSha, 40, "headSha").toLowerCase();
  const outcome = cleanText(input.outcome, 40, "outcome");
  if (!isRepo(repo) || !isSha(headSha)) {
    throw new Error("review repo or headSha is invalid");
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
    outcome,
    reviewId: optionalCleanText(input.reviewId, 120, "reviewId"),
    coverageComplete: input.coverageComplete === true,
    retryAllowed: input.retryAllowed === true,
    findings,
    summary: optionalCleanText(input.summary, 1000, "summary"),
    claimRef: optionalCleanText(input.claimRef, 500, "claimRef"),
  };
}

export function createState(eventInput, policyInput, now = Date.now()) {
  const event = normalizePullRequestEvent(eventInput);
  const policy = normalizePolicy(policyInput);
  const currentMergePolicyDigest = mergePolicyDigest(policy, event.repo);
  if (
    policy.mergeAuthorization &&
    policy.mergeAuthorization.policyDigest !== currentMergePolicyDigest
  ) {
    throw new Error("mergeAuthorization.policyDigest does not match repository policy");
  }
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
    headRef: event.headRef,
    phase: PHASE.REVIEW_QUEUED,
    cycle: 0,
    retryCount: 0,
    infrastructureRetryCount: 0,
    infrastructureRetryAt: null,
    infrastructureLastFailure: null,
    protocolRetryCount: 0,
    protocolRetryAt: null,
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
    githubUpdatedAt: event.githubUpdatedAt,
    pendingGithubReconciliation: null,
    pendingPublication: null,
    remediatorProfile: policy.remediatorProfile,
    remediatorProfileDigest: policy.remediatorProfile?.digest ?? null,
    configuredRemediatorProfileDigest: policy.remediatorProfile?.digest ?? null,
    mergeAuthorization: policy.mergeAuthorization,
    configuredMergeAuthorizationDigest: policy.mergeAuthorization?.digest ?? null,
    mergePolicyDigest: currentMergePolicyDigest,
    brokerRepoAlias: policy.brokerRepoAlias,
    autoMergeBaseBranches: policy.autoMergeBaseBranches,
    autoMergeMethod: policy.autoMergeMethod,
    activeWorker: null,
    reviewLease: null,
    fixerAttestation: null,
    primaryFixerFailure: null,
    review: null,
    findings: [],
    wait: null,
    blocker: null,
    mergeReady: null,
    mergeGates: null,
    prEffects: "none",
    latestExternalMilestone: null,
    externalMilestoneHistory: [],
    lastTerminalEnvelope: null,
    terminalEnvelopeHistory: [],
    terminalSupersession: null,
    notificationDeliveries: [],
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

function reviewLeaseBindingReason(lease, result) {
  if (!lease || lease.kind !== "review") {
    return "unsolicited_review_result";
  }
  if (lease.claimRef && result.claimRef !== lease.claimRef) {
    return "mismatched_review_claim";
  }
  if (lease.reviewId && result.reviewId !== lease.reviewId) {
    return "mismatched_review_id";
  }
  return null;
}

export function matchingCurrentReviewLease(state) {
  if (!state || typeof state !== "object") {
    return null;
  }
  if (
    state.activeWorker?.kind === "review" &&
    state.activeWorker.headSha === state.headSha &&
    state.activeWorker.cycle === state.cycle
  ) {
    return state.activeWorker;
  }
  if (
    state.reviewLease?.kind === "review" &&
    state.reviewLease.headSha === state.headSha &&
    state.reviewLease.cycle === state.cycle
  ) {
    return state.reviewLease;
  }
  return null;
}

export function holdsReviewLease(state) {
  if (!state || typeof state !== "object") {
    return false;
  }
  if (state.activeWorker?.kind === "review") {
    return true;
  }
  return state.reviewLease?.kind === "review";
}

export function holdsWorkerLease(state) {
  return Boolean(state?.activeWorker) || Boolean(state?.orphanedWorker) || holdsReviewLease(state);
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
  const currentMergePolicyDigest = mergePolicyDigest(policy, event.repo);
  if (
    policy.mergeAuthorization &&
    policy.mergeAuthorization.policyDigest !== currentMergePolicyDigest
  ) {
    return blockState(state, "merge_authorization_policy_digest_mismatch", now, event.eventId);
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
  const baseChanged = event.baseSha !== state.baseSha || event.baseRef !== state.baseRef;
  if (
    (event.headSha !== state.headSha || baseChanged) &&
    event.eventId.startsWith("github:") &&
    event.authoritative !== true
  ) {
    if (
      Number.isSafeInteger(state.githubUpdatedAt) &&
      event.githubUpdatedAt < state.githubUpdatedAt
    ) {
      return { changed: false, state, effect: "none", reason: "stale_github_event" };
    }
    if (
      Number.isSafeInteger(state.githubUpdatedAt) &&
      event.githubUpdatedAt === state.githubUpdatedAt
    ) {
      const ambiguous = appendSeenEvent(
        {
          ...state,
          pendingGithubReconciliation: {
            eventId: event.eventId,
            action: event.action,
            headSha: event.headSha,
            baseSha: event.baseSha,
            baseRef: event.baseRef,
            headRepo: event.headRepo,
            githubUpdatedAt: event.githubUpdatedAt,
            detectedAt: now,
          },
          wait: {
            kind: "github_head_reconciliation",
            since: now,
            eventId: event.eventId,
          },
          updatedAt: now,
        },
        event.eventId,
      );
      return {
        changed: true,
        state: ambiguous,
        effect: "reconcile",
        reason: "github_event_order_ambiguous",
      };
    }
  }
  if (event.headSha === state.headSha && !baseChanged) {
    if (isTerminalState(state)) {
      return {
        changed: true,
        state: appendSeenEvent(
          {
            ...state,
            githubUpdatedAt: maxGithubUpdatedAt(state, event),
            pendingGithubReconciliation: null,
            wait: null,
            updatedAt: now,
          },
          event.eventId,
        ),
        effect: "none",
        reason: "terminal_same_head",
      };
    }
    return {
      changed: true,
      state: appendSeenEvent(
        {
          ...state,
          githubUpdatedAt: maxGithubUpdatedAt(state, event),
          pendingGithubReconciliation: null,
          wait: null,
          updatedAt: now,
        },
        event.eventId,
      ),
      effect: "none",
      reason: "same_head_event",
    };
  }
  const changeReason =
    event.headSha !== state.headSha ? "pull_request_head_changed" : "pull_request_base_changed";
  const orphanedWorker = state.activeWorker
    ? {
        ...state.activeWorker,
        reason: changeReason,
        clearedAt: now,
      }
    : state.orphanedWorker
      ? {
          ...state.orphanedWorker,
          reason: changeReason,
          clearedAt: now,
        }
      : state.reviewLease?.kind === "review"
        ? {
            kind: "review",
            sessionKey: state.reviewLease.sessionKey,
            flowId: state.reviewLease.flowId ?? null,
            headSha: state.reviewLease.headSha,
            cycle: state.reviewLease.cycle,
            reservedAt: state.reviewLease.reservedAt,
            runId: null,
            taskId: null,
            reason: changeReason,
            clearedAt: now,
          }
        : (state.orphanedWorker ?? null);
  const policyDeadline = now + policy.wallTimeMinutes * 60_000;
  const deadlineAt = Number.isFinite(state.deadlineAt)
    ? Math.min(state.deadlineAt, policyDeadline)
    : policyDeadline;
  if (state.pendingPublication && !event.eventId.startsWith("github:")) {
    return {
      changed: false,
      state,
      effect: "wait",
      reason: "pending_publication_requires_github_confirmation",
    };
  }
  const pendingPublication =
    event.eventId.startsWith("github:") &&
    event.action === "synchronize" &&
    state.pendingPublication?.headSha === event.headSha &&
    Number.isInteger(state.pendingPublication?.cycle) &&
    state.pendingPublication.cycle === state.cycle + 1
      ? state.pendingPublication
      : null;
  const next = appendSeenEvent(
    {
      ...supersedeExternalMilestone(state, now),
      headSha: event.headSha,
      baseSha: event.baseSha,
      baseRef: event.baseRef,
      headRef: event.headRef,
      phase: PHASE.REVIEW_QUEUED,
      cycle: pendingPublication?.cycle ?? 0,
      retryCount: 0,
      infrastructureRetryCount: 0,
      infrastructureRetryAt: null,
      infrastructureLastFailure: null,
      protocolRetryCount: 0,
      protocolRetryAt: null,
      orphanedWorker,
      maxCycles: policy.maxCycles,
      maxRetries: policy.maxRetries,
      wallTimeMinutes: policy.wallTimeMinutes,
      startedAt: Number.isFinite(state.startedAt) ? state.startedAt : now,
      cycleStartedAt: now,
      deadlineAt,
      lastGhostCleanup: null,
      workspacePreflight: null,
      mode: policy.mode,
      reviewActor: policy.reviewActor,
      authorActor: policy.authorActor,
      fixerModel: policy.fixerModel,
      fixerFallbackModel: policy.fixerFallbackModel,
      publisherBoundary: publisherBoundaryFromPolicy(policy),
      githubUpdatedAt: maxGithubUpdatedAt(state, event),
      pendingGithubReconciliation: null,
      pendingPublication: null,
      remediatorProfile: policy.remediatorProfile,
      remediatorProfileDigest: policy.remediatorProfile?.digest ?? null,
      configuredRemediatorProfileDigest: policy.remediatorProfile?.digest ?? null,
      mergeAuthorization: policy.mergeAuthorization,
      configuredMergeAuthorizationDigest: policy.mergeAuthorization?.digest ?? null,
      mergePolicyDigest: currentMergePolicyDigest,
      brokerRepoAlias: policy.brokerRepoAlias,
      autoMergeBaseBranches: policy.autoMergeBaseBranches,
      autoMergeMethod: policy.autoMergeMethod,
      activeWorker: null,
      reviewLease:
        state.reviewLease?.kind === "review"
          ? {
              ...state.reviewLease,
              reason: "pull_request_head_changed",
              supersededByHeadSha: event.headSha,
            }
          : null,
      fixerAttestation: pendingPublication?.fixerAttestation ?? null,
      primaryFixerFailure: pendingPublication ? state.primaryFixerFailure : null,
      review: null,
      findings: [],
      wait: null,
      blocker: null,
      mergeReady: null,
      mergeGates: null,
      terminalSupersession: null,
      updatedAt: now,
    },
    event.eventId,
  );
  return {
    changed: true,
    state: next,
    effect: "continue",
    reason: pendingPublication
      ? "published_head_confirmed"
      : event.headSha === state.headSha
        ? "base_changed"
        : "new_head",
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
    if (state.reviewLease?.kind === "review" && state.reviewLease.headSha === result.headSha) {
      const staleBinding = reviewLeaseBindingReason(state.reviewLease, result);
      if (staleBinding) {
        return { changed: false, state, effect: "none", reason: staleBinding };
      }
      return {
        changed: true,
        state: appendSeenEvent(
          {
            ...state,
            reviewLease: null,
            orphanedWorker:
              state.orphanedWorker?.headSha === result.headSha ? null : state.orphanedWorker,
            updatedAt: now,
          },
          result.eventId,
        ),
        effect: "none",
        reason: "stale_head_lease_released",
      };
    }
    return {
      changed: false,
      state,
      effect: "none",
      reason: "stale_head_result",
    };
  }
  if (
    !new Set([PHASE.REVIEW_QUEUED, PHASE.REVIEW_RUNNING, PHASE.REVIEW_WAITING]).has(state.phase)
  ) {
    return { changed: false, state, effect: "none", reason: "unexpected_review_phase" };
  }
  const lease = matchingCurrentReviewLease(state);
  if (!lease) {
    return { changed: false, state, effect: "none", reason: "unsolicited_review_result" };
  }
  const bindingReason = reviewLeaseBindingReason(lease, result);
  if (bindingReason) {
    return { changed: false, state, effect: "none", reason: bindingReason };
  }
  if (result.outcome === "approved" && !result.reviewId) {
    return { changed: false, state, effect: "none", reason: "approval_without_review_id" };
  }
  const activeReviewWorker =
    state.activeWorker?.kind === "review"
      ? {
          ...state.activeWorker,
          reason: "review_completion_received",
          clearedAt: now,
        }
      : null;
  const withEvent = appendSeenEvent(
    activeReviewWorker
      ? {
          ...state,
          activeWorker: null,
          orphanedWorker: activeReviewWorker,
        }
      : state,
    result.eventId,
  );
  const milestone = reviewMilestone(state, result, now);
  const withReviewEffect = milestone ? recordExternalMilestone(withEvent, milestone) : withEvent;
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
      return blockState(withReviewEffect, "approval_without_complete_zero_finding_coverage", now);
    }
    const next = {
      ...withReviewEffect,
      phase: PHASE.MERGE_READY,
      activeWorker: null,
      reviewLease: null,
      infrastructureRetryCount: 0,
      infrastructureRetryAt: null,
      infrastructureLastFailure: null,
      protocolRetryCount: 0,
      protocolRetryAt: null,
      orphanedWorker: withReviewEffect.orphanedWorker ?? null,
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
        mergeAuthorized: false,
        mergeMethod: state.autoMergeMethod ?? "merge",
        authorizationDigest: null,
        authorizationAdoptedAt: null,
      },
      updatedAt: now,
    };
    return {
      changed: true,
      state: next,
      effect: "merge_ready",
      reason: "approved",
    };
  }
  if (result.outcome === "changes_requested") {
    if (!result.coverageComplete || result.findings.length === 0) {
      return blockState(withReviewEffect, "changes_requested_without_complete_findings", now);
    }
    if (!findingsAreActionable(result.findings)) {
      return blockState(withReviewEffect, "changes_requested_without_actionable_paths", now);
    }
    const reviewed = {
      ...withReviewEffect,
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
      reviewLease: null,
      fixerAttestation: null,
      primaryFixerFailure: null,
      review,
      findings: result.findings,
      wait: null,
      blocker: null,
      retryCount: 0,
      infrastructureRetryCount: 0,
      infrastructureRetryAt: null,
      infrastructureLastFailure: null,
      protocolRetryCount: 0,
      protocolRetryAt: null,
      orphanedWorker: reviewed.orphanedWorker ?? null,
      updatedAt: now,
    };
    return { changed: true, state: next, effect: "continue", reason: "findings_ready" };
  }
  if (result.outcome === "failed_retryable") {
    if (!result.retryAllowed || state.retryCount >= state.maxRetries) {
      return blockState(withReviewEffect, "review_retry_not_allowed_or_exhausted", now);
    }
    const budget = budgetBlock(withReviewEffect, now);
    if (budget) {
      return budget;
    }
    const next = {
      ...withReviewEffect,
      phase: PHASE.REVIEW_QUEUED,
      activeWorker: null,
      reviewLease: null,
      review,
      wait: null,
      blocker: null,
      retryCount: state.retryCount + 1,
      updatedAt: now,
    };
    return { changed: true, state: next, effect: "continue", reason: "retry_review" };
  }
  return blockState(withReviewEffect, "review_failed_terminal", now);
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

export function reserveWorker(state, kind, sessionKey, now = Date.now(), flowId = null) {
  if (!isLifecycleState(state)) {
    throw new Error("stored lifecycle state is invalid");
  }
  if (state.activeWorker) {
    return { changed: false, state, reason: "worker_already_reserved" };
  }
  if (state.reviewLease?.kind === "review" && state.reviewLease.headSha !== state.headSha) {
    return { changed: false, state, effect: "wait", reason: "prior_review_lease_held" };
  }
  const expectedKind = workerKindForPhase(state.phase);
  if (!expectedKind || expectedKind !== kind) {
    return { changed: false, state, reason: "phase_not_dispatchable" };
  }
  const protocolRetryAt = Number.isFinite(state.protocolRetryAt) ? state.protocolRetryAt : null;
  if (Number.isFinite(protocolRetryAt) && protocolRetryAt > now) {
    return { changed: false, state, effect: "wait", reason: "protocol_backoff" };
  }
  const infrastructureRetryAt = Number.isFinite(state.infrastructureRetryAt)
    ? state.infrastructureRetryAt
    : null;
  const budget = budgetBlock(state, now);
  if (budget) {
    return budget;
  }
  if (Number.isFinite(infrastructureRetryAt) && infrastructureRetryAt > now) {
    return { changed: false, state, effect: "wait", reason: "infrastructure_backoff" };
  }
  let baseState =
    Number.isFinite(infrastructureRetryAt) || Number.isFinite(protocolRetryAt)
      ? {
          ...state,
          infrastructureRetryAt: null,
          protocolRetryAt: null,
          wait: null,
        }
      : state;
  if (kind === "remediation" && baseState.cycle >= baseState.maxCycles) {
    return blockState(baseState, "review_fix_cycle_budget_exhausted", now);
  }
  const next = {
    ...baseState,
    phase: kind === "review" ? PHASE.REVIEW_RUNNING : PHASE.REMEDIATION_RUNNING,
    activeWorker: {
      flowId: flowId ? cleanText(flowId, 200, "flowId") : null,
      kind,
      sessionKey: cleanText(sessionKey, 500, "sessionKey"),
      headSha: state.headSha,
      cycle: state.cycle,
      reservedAt: now,
      runId: null,
      taskId: null,
      profileDigest: kind === "remediation" ? (state.remediatorProfileDigest ?? null) : null,
      claimRef: kind === "review" ? `mprl-review:${state.headSha}:${state.cycle}:${now}` : null,
    },
    wait: null,
    blocker: null,
    updatedAt: now,
  };
  return { changed: true, state: next, effect: "start_worker", reason: "reserved" };
}

export function attachWorkerRun(state, sessionKey, runId, taskId, now = Date.now()) {
  if (!state.activeWorker || state.activeWorker.sessionKey !== sessionKey) {
    return { changed: false, state, reason: "worker_reservation_changed" };
  }
  return {
    changed: true,
    state: {
      ...state,
      activeWorker: {
        ...state.activeWorker,
        runId: cleanText(runId, 200, "runId"),
        taskId: taskId ? cleanText(taskId, 200, "taskId") : null,
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
  if (worker.kind === "review" && report.claimRef !== worker.claimRef) {
    throw new Error("worker report claim does not match controller-issued claim");
  }
  if (
    worker.kind === "remediation" &&
    worker.profileDigest &&
    report.profileDigest !== worker.profileDigest
  ) {
    throw new Error("worker report remediator profile digest is stale");
  }
  return worker;
}

function primaryFixerFailureFromReport(state, report, now) {
  const worker = state.activeWorker;
  const primary = state.fixerModel ?? PRIMARY_FIXER_MODEL;
  if (
    !worker?.flowId ||
    !worker?.runId ||
    !worker.taskId ||
    report.fixerModel !== primary ||
    !report.fixerAttested ||
    !report.fixerAttestationRef ||
    !FIXER_FALLBACK_INFRASTRUCTURE_REASONS.has(report.fixerFallbackReason) ||
    report.fixerPrimaryFailureRef ||
    state.primaryFixerFailure ||
    report.newHeadSha ||
    report.testsPassed ||
    report.publicationConfirmed ||
    report.verificationComplete
  ) {
    return null;
  }
  return {
    ref: `primary-failure:${worker.flowId}:${state.headSha}:${state.cycle}:${worker.taskId}`,
    flowId: worker.flowId,
    reason: report.fixerFallbackReason,
    primaryModel: primary,
    modelAttestationRef: report.fixerAttestationRef,
    headSha: state.headSha,
    cycle: state.cycle,
    workerSessionKey: worker.sessionKey,
    workerRunId: worker.runId,
    workerTaskId: worker.taskId,
    recordedAt: now,
    consumedAt: null,
    consumedBy: null,
  };
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
    const primaryFailure = state.primaryFixerFailure;
    if (
      !FIXER_FALLBACK_INFRASTRUCTURE_REASONS.has(report.fixerFallbackReason) ||
      !report.fixerPrimaryFailureRef ||
      !primaryFailure ||
      primaryFailure.consumedAt !== null ||
      primaryFailure.ref !== report.fixerPrimaryFailureRef ||
      primaryFailure.reason !== report.fixerFallbackReason ||
      primaryFailure.primaryModel !== primary ||
      primaryFailure.flowId !== state.activeWorker?.flowId ||
      primaryFailure.headSha !== state.headSha ||
      primaryFailure.cycle !== state.cycle ||
      !primaryFailure.workerSessionKey ||
      !primaryFailure.workerRunId ||
      !primaryFailure.workerTaskId ||
      primaryFailure.ref !==
        `primary-failure:${primaryFailure.flowId}:${primaryFailure.headSha}:` +
          `${primaryFailure.cycle}:${primaryFailure.workerTaskId}`
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

function consumedPrimaryFixerFailure(state, fixerAttestation, now) {
  if (!fixerAttestation?.fallbackUsed || !state.primaryFixerFailure) {
    return null;
  }
  return {
    ...state.primaryFixerFailure,
    consumedAt: now,
    consumedBy: {
      sessionKey: state.activeWorker?.sessionKey ?? null,
      flowId: state.activeWorker?.flowId ?? null,
      runId: state.activeWorker?.runId ?? null,
      taskId: state.activeWorker?.taskId ?? null,
    },
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
    profileDigest: optionalCleanText(reportInput.profileDigest, 64, "profileDigest"),
    outcomeClass: optionalCleanText(reportInput.outcomeClass, 80, "outcomeClass"),
    finalStage: optionalCleanText(reportInput.finalStage, 120, "finalStage"),
    findings: sanitizeFindings(reportInput.findings ?? []),
  };
  if (
    report.outcomeClass &&
    !new Set([
      "success",
      "preflight_failure",
      "policy_rejection",
      "test_failure",
      "publication_failure",
      "execution_failure",
      "protocol_violation",
    ]).has(report.outcomeClass)
  ) {
    throw new Error("outcomeClass is invalid");
  }
  const worker = assertWorkerReportMatches(state, report, callerSessionKey);
  const reportedWorker = {
    ...worker,
    reason: "worker_report_received",
    clearedAt: now,
  };
  const cleared = recordTerminalEnvelope(
    {
      ...state,
      activeWorker: null,
      infrastructureRetryCount: 0,
      infrastructureRetryAt: null,
      infrastructureLastFailure: null,
      protocolRetryCount: 0,
      protocolRetryAt: null,
      orphanedWorker: reportedWorker,
      pendingPublication: null,
      updatedAt: now,
    },
    terminalEnvelope(state, worker, report, now),
  );

  if (report.kind === "review") {
    if (report.outcome === "waiting_review") {
      const next = {
        ...cleared,
        phase: PHASE.REVIEW_WAITING,
        reviewLease: {
          kind: "review",
          flowId: worker.flowId ?? null,
          sessionKey: worker.sessionKey,
          headSha: state.headSha,
          cycle: state.cycle,
          claimRef: worker.claimRef,
          reviewId: report.reviewId ?? null,
          reservedAt: Number.isFinite(worker.reservedAt) ? worker.reservedAt : now,
          waitingSince: now,
        },
        wait: {
          kind: "broker_review",
          headSha: state.headSha,
          reviewId: report.reviewId ?? null,
          claimRef: worker.claimRef,
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
      const claimRef = worker.claimRef;
      return applyReviewResult(
        {
          ...cleared,
          reviewLease: {
            kind: "review",
            flowId: worker.flowId ?? null,
            sessionKey: worker.sessionKey,
            headSha: worker.headSha,
            cycle: worker.cycle,
            claimRef,
            reviewId: report.reviewId ?? state.reviewLease?.reviewId ?? null,
            reservedAt: Number.isFinite(worker.reservedAt) ? worker.reservedAt : now,
          },
        },
        {
          eventId: `worker:${worker.runId ?? worker.sessionKey}:${report.outcome}`,
          repo: state.repo,
          prNumber: state.prNumber,
          headSha: state.headSha,
          outcome: report.outcome,
          reviewId: report.reviewId,
          claimRef,
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
  if (report.outcome === "primary_fixer_failed_retryable") {
    const primaryFixerFailure = primaryFixerFailureFromReport(state, report, now);
    if (!primaryFixerFailure) {
      return blockState(cleared, "primary_fixer_failure_evidence_invalid", now);
    }
    return {
      changed: true,
      state: {
        ...cleared,
        phase: PHASE.REMEDIATION_QUEUED,
        primaryFixerFailure,
        infrastructureRetryCount: Math.max(0, Number(state.infrastructureRetryCount) || 0) + 1,
        infrastructureRetryAt: null,
        infrastructureLastFailure: `primary_fixer:${primaryFixerFailure.reason}`,
        wait: null,
        blocker: null,
      },
      effect: "continue",
      reason: "primary_fixer_failure_recorded",
    };
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
    const published = recordExternalMilestone(cleared, {
      kind: "commit_published",
      headSha: report.newHeadSha,
      observedAt: now,
      observedRevision: null,
      url: `https://github.com/${state.repo}/pull/${state.prNumber}/commits/${report.newHeadSha}`,
      receipt: { attestationRef: report.fixerAttestationRef },
    });
    const next = {
      ...published,
      phase: PHASE.WAITING_HEAD_EVENT,
      pendingPublication: {
        headSha: report.newHeadSha,
        cycle: nextCycle,
        fixerAttestation,
      },
      wait: {
        kind: "pull_request_head_confirmation",
        headSha: report.newHeadSha,
        since: now,
      },
      review: null,
      findings: [],
      primaryFixerFailure: consumedPrimaryFixerFailure(state, fixerAttestation, now),
      blocker: null,
    };
    return { changed: true, state: next, effect: "wait", reason: "awaiting_head_confirmation" };
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
        deadlineAt: state.deadlineAt,
        fixerAttestation,
        primaryFixerFailure: consumedPrimaryFixerFailure(state, fixerAttestation, now),
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
  const cleared = recordTerminalEnvelope(
    { ...state, activeWorker: null, updatedAt: now },
    terminalEnvelope(
      state,
      state.activeWorker,
      { outcome: "execution_failure", summary: normalizedReason },
      now,
      { outcomeClass: "execution_failure", finalStage: `${kind}_execution` },
    ),
  );
  if (classifyWorkerFailure(normalizedReason) === "infrastructure") {
    if (now > state.deadlineAt) {
      return blockState(cleared, "wall_time_budget_exhausted", now);
    }
    const attempt = Math.max(0, Number(state.infrastructureRetryCount) || 0) + 1;
    if (attempt > MAX_INFRASTRUCTURE_RETRIES) {
      return blockState(cleared, `infrastructure_retry_exhausted:${normalizedReason}`, now);
    }
    const retryAt = Math.min(now + infrastructureBackoffMs(attempt), state.deadlineAt + 1);
    return {
      changed: true,
      state: {
        ...cleared,
        phase: retryPhase(state, kind),
        infrastructureRetryCount: attempt,
        infrastructureRetryAt: retryAt,
        infrastructureLastFailure: normalizedReason,
        orphanedWorker: {
          ...state.activeWorker,
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

export function applyWorkerProtocolViolation(state, callerSessionKey, stage, now = Date.now()) {
  if (!state.activeWorker || state.activeWorker.sessionKey !== callerSessionKey) {
    return { changed: false, state, effect: "none", reason: "stale_worker_protocol_violation" };
  }
  const worker = state.activeWorker;
  const finalStage = cleanText(stage, 120, "stage");
  const reason = `worker_protocol_violation:${finalStage}`;
  const cleared = recordTerminalEnvelope(
    { ...state, activeWorker: null, updatedAt: now },
    terminalEnvelope(state, worker, { outcome: reason, summary: reason }, now, {
      outcomeClass: "protocol_violation",
      finalStage,
    }),
  );
  const attempt = Math.max(0, Number(state.protocolRetryCount) || 0) + 1;
  if (attempt > MAX_PROTOCOL_RETRIES) {
    return blockState(cleared, `${reason}:retry_exhausted`, now);
  }
  const retryAt = now + INFRASTRUCTURE_BACKOFF_BASE_MS;
  return {
    changed: true,
    state: {
      ...cleared,
      phase: retryPhase(state, worker.kind),
      protocolRetryCount: attempt,
      protocolRetryAt: retryAt,
      orphanedWorker: {
        ...worker,
        reason,
        clearedAt: now,
      },
      wait: { kind: "protocol_backoff", reason, attempt, retryAt },
      blocker: null,
    },
    effect: "wait",
    reason: "retry_worker_protocol_violation",
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
  if (state.pendingGithubReconciliation) {
    if (now > state.deadlineAt) {
      return blockState(state, "github_head_reconciliation_deadline_exhausted", now);
    }
    return {
      changed: false,
      state,
      effect: "reconcile",
      reason: "github_head_reconciliation_pending",
    };
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
      if (state.wait?.kind === "check_suite") {
        return { changed: false, state, effect: "wait", reason: "check_suite_event_wait" };
      }
      return { changed: false, state, effect: "continue", reason: "queued_merge" };
    }
    if (workerKindForPhase(state.phase)) {
      if (state.reviewLease?.kind === "review" && state.reviewLease.headSha !== state.headSha) {
        if (now > state.deadlineAt) {
          return blockState(state, "review_wait_deadline_exhausted", now);
        }
        return {
          changed: false,
          state,
          effect: "wait",
          reason: "prior_review_lease_held",
        };
      }
      const budget = budgetBlock(state, now);
      if (budget) {
        return budget;
      }
      const protocolRetryAt = Number.isFinite(state.protocolRetryAt) ? state.protocolRetryAt : null;
      if (Number.isFinite(protocolRetryAt) && protocolRetryAt > now) {
        return { changed: false, state, effect: "wait", reason: "protocol_backoff" };
      }
      if (Number.isFinite(protocolRetryAt)) {
        return {
          changed: true,
          state: {
            ...state,
            protocolRetryAt: null,
            wait: null,
            updatedAt: now,
          },
          effect: "continue",
          reason: "protocol_backoff_elapsed",
        };
      }
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
      if (now > state.deadlineAt) {
        return blockState(state, "review_wait_deadline_exhausted", now);
      }
      return {
        changed: false,
        state,
        effect: "wait",
        reason: "review_in_progress",
      };
    }
    if (state.phase === PHASE.WAITING_HEAD_EVENT && now > state.deadlineAt) {
      return blockState(state, "head_confirmation_deadline_exhausted", now);
    }
    return { changed: false, state, effect: "wait", reason: "external_wait" };
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
  if (workerTask?.status === "succeeded") {
    if (state.activeWorker.kind === "remediation" && !findingsAreActionable(state.findings)) {
      return blockState(state, "findings_unusable", now);
    }
    return applyWorkerProtocolViolation(
      state,
      state.activeWorker.sessionKey,
      state.activeWorker.kind === "remediation" ? "remediation_evidence" : "review_report",
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

export function blockState(state, reason, now = Date.now(), eventId) {
  const blocker = cleanText(reason, 1000, "blocker");
  const next = appendSeenEvent(
    {
      ...state,
      phase: PHASE.BLOCKED,
      activeWorker: null,
      reviewLease: null,
      wait: { kind: "manual_intervention", since: now },
      blocker,
      mergeReady: null,
      terminalSupersession: state.terminalSupersession ?? {
        schemaVersion: 1,
        eventId: `terminal:${state.flowId ?? `${state.repo}#${state.prNumber}`}:${state.headSha}:blocked`,
        flowId: state.flowId ?? null,
        repository: state.repo,
        prNumber: state.prNumber,
        headSha: state.headSha,
        phase: PHASE.BLOCKED,
        reason: blocker,
        emittedAt: now,
      },
      updatedAt: now,
    },
    eventId,
  );
  return { changed: true, state: next, effect: "blocked", reason: next.blocker };
}

export function flowMatches(state, repo, prNumber) {
  return isLifecycleState(state) && state.repo === repo && state.prNumber === prNumber;
}
