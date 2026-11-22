import {
  FALLBACK_FIXER_MODEL,
  INFRASTRUCTURE_BACKOFF_BASE_MS,
  INFRASTRUCTURE_BACKOFF_MAX_MS,
  INFRASTRUCTURE_FAILURE_PATTERNS,
  MERGE_AUTHORIZATION_SCHEMA_VERSION,
  PHASE,
  PRIMARY_FIXER_MODEL,
  REMEDIATOR_PROFILE_SCHEMA_VERSION,
} from "./controller-constants.mjs";
import { isLifecycleState } from "./controller-state.mjs";
import {
  cleanAbsolutePath,
  cleanRelativePath,
  cleanText,
  digestObject,
  isRepo,
  normalizeStrings,
  normalizeUniqueStrings,
  optionalCleanText,
  positiveInteger,
} from "./controller-validation.mjs";

export function classifyWorkerFailure(reason) {
  const normalized = cleanText(reason, 500, "reason").toLowerCase();
  return INFRASTRUCTURE_FAILURE_PATTERNS.some((pattern) => pattern.test(normalized))
    ? "infrastructure"
    : "content";
}

export function infrastructureBackoffMs(attempt) {
  const exponent = Math.max(0, Math.min(10, attempt - 1));
  return Math.min(INFRASTRUCTURE_BACKOFF_MAX_MS, INFRASTRUCTURE_BACKOFF_BASE_MS * 2 ** exponent);
}

export function retryPhase(state, kind) {
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

export function publisherBoundaryFromPolicy(policy) {
  return {
    actor: policy.authorActor,
    brokerId: policy.publisherBrokerId ?? null,
    attestationRef: policy.publisherAttestationRef ?? null,
    ready: Boolean(policy.publisherBrokerId && policy.publisherAttestationRef),
  };
}

export function infrastructureReasonFromBlocker(blocker) {
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
