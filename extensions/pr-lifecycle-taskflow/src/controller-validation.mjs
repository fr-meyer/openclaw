import { createHash } from "node:crypto";
import {
  MAX_FINDINGS,
  MAX_SEEN_EVENTS,
  MAX_TERMINAL_ENVELOPES,
  REPO_PATTERN,
  SAFE_TEXT_PATTERN,
  SHA_PATTERN,
  TERMINAL_ENVELOPE_SCHEMA_VERSION,
} from "./controller-constants.mjs";

export function canonicalJson(value) {
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalJson(item)).join(",")}]`;
  }
  if (value && typeof value === "object") {
    return `{${Object.keys(value)
      .toSorted()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

export function digestObject(value) {
  return createHash("sha256").update(canonicalJson(value)).digest("hex");
}

export function cleanRelativePath(value, field) {
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

export function cleanAbsolutePath(value, field) {
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

export function normalizeUniqueStrings(value, field, maxItems, mapper) {
  if (!Array.isArray(value) || value.length === 0 || value.length > maxItems) {
    throw new Error(`${field} must be a non-empty array with at most ${maxItems} entries`);
  }
  return [...new Set(value.map((item, index) => mapper(item, `${field}[${index}]`)))];
}

export function normalizeStrings(value, field, maxItems, mapper) {
  if (!Array.isArray(value) || value.length === 0 || value.length > maxItems) {
    throw new Error(`${field} must be a non-empty array with at most ${maxItems} entries`);
  }
  return value.map((item, index) => mapper(item, `${field}[${index}]`));
}

export function isSha(value) {
  return typeof value === "string" && SHA_PATTERN.test(value);
}

export function isRepo(value) {
  return typeof value === "string" && REPO_PATTERN.test(value);
}

export function cleanText(value, maxLength, field) {
  if (typeof value !== "string") {
    throw new Error(`${field} must be a string`);
  }
  const normalized = value.trim();
  if (!normalized || normalized.length > maxLength || !SAFE_TEXT_PATTERN.test(normalized)) {
    throw new Error(`${field} is invalid`);
  }
  return normalized;
}

export function optionalCleanText(value, maxLength, field) {
  if (value === undefined || value === null || value === "") {
    return undefined;
  }
  return cleanText(value, maxLength, field);
}

export function cleanRepositoryRelativePath(value, field) {
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

export function positiveInteger(value, field) {
  if (!Number.isInteger(value) || value < 1) {
    throw new Error(`${field} must be a positive integer`);
  }
  return value;
}

export function appendSeenEvent(state, eventId) {
  if (!eventId || state.seenEventIds.includes(eventId)) {
    return state;
  }
  return {
    ...state,
    seenEventIds: [...state.seenEventIds, eventId].slice(-MAX_SEEN_EVENTS),
  };
}

export function optionalGithubUpdatedAt(value, field) {
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

export function githubNumericId(value, field) {
  const text = Number.isSafeInteger(value) ? String(value) : value;
  if (typeof text !== "string" || !/^[1-9]\d{0,39}$/.test(text)) {
    throw new Error(`${field} must be a positive GitHub numeric identifier`);
  }
  return text;
}

export function compareGithubNumericIds(left, right) {
  const normalizedLeft = left.replace(/^0+/, "") || "0";
  const normalizedRight = right.replace(/^0+/, "") || "0";
  if (normalizedLeft.length !== normalizedRight.length) {
    return normalizedLeft.length < normalizedRight.length ? -1 : 1;
  }
  return normalizedLeft === normalizedRight ? 0 : normalizedLeft < normalizedRight ? -1 : 1;
}

export function staleCheckSuiteEvent(wait, event) {
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

export function maxGithubUpdatedAt(state, event) {
  if (
    Number.isSafeInteger(event.githubUpdatedAt) &&
    (!Number.isSafeInteger(state.githubUpdatedAt) || event.githubUpdatedAt > state.githubUpdatedAt)
  ) {
    return event.githubUpdatedAt;
  }
  return state.githubUpdatedAt ?? null;
}

export function recordExternalMilestone(state, milestone) {
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

export function reviewMilestone(state, result, now) {
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

export function terminalOutcomeClass(outcome) {
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

export function terminalEnvelope(state, worker, report, now, overrides = {}) {
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

export function recordTerminalEnvelope(state, envelope) {
  const history = [
    ...(Array.isArray(state.terminalEnvelopeHistory) ? state.terminalEnvelopeHistory : []),
    ...(state.lastTerminalEnvelope ? [state.lastTerminalEnvelope] : []),
  ].slice(-MAX_TERMINAL_ENVELOPES);
  return { ...state, lastTerminalEnvelope: envelope, terminalEnvelopeHistory: history };
}

export function supersedeExternalMilestone(state, now) {
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
