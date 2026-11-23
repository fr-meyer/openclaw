import assert from "node:assert/strict";
import { applyReviewResult, reserveWorker } from "../src/controller.mjs";

export const SHA_A = "a".repeat(40);
export const SHA_B = "b".repeat(40);
export const SHA_C = "c".repeat(40);
export const NOW = 1_788_000_000_000;
export const githubTimestamp = (second) =>
  new Date(Date.UTC(2026, 8, 5, 0, 0, second)).toISOString();

export function remediatorProfile(overrides = {}) {
  return {
    schemaVersion: 1,
    repository: "example-org/example-repo",
    pullRequests: [42],
    headBranchPattern: "^feat/",
    baseBranches: ["dev"],
    seedWorkspace: "/workspace/repo",
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
    authorizedAt: NOW - 1_000,
    expiresAt: NOW + 60_000,
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

export function policy(overrides = {}) {
  return {
    enabled: true,
    mode: "active",
    workspace: "/workspace/repo",
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
    updatedAt: githubTimestamp(1),
    ...overrides,
  };
}

export function reviewResult(overrides = {}) {
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
    summary: "Projected cycles can exceed the wall-time budget.",
    path: "src/example-repo/ritournelle/supervisor.py",
    line: 42,
    evidence: "Bounded test fixture reproduces the issue.",
    ...overrides,
  };
}

export function fixerProof(overrides = {}) {
  return {
    fixerModel: "primary-fixer",
    fixerAttested: true,
    fixerAttestationRef: "sha256:" + "d".repeat(64),
    ...overrides,
  };
}

export function remediationBinding(state) {
  return { profileDigest: state.activeWorker?.profileDigest };
}

export function reserve(
  state,
  kind = "review",
  sessionKey = "agent:owner-agent:subagent:mprl-flow-0-review",
  now = NOW + 10,
) {
  const reserved = reserveWorker(state, kind, sessionKey, now);
  assert.equal(reserved.changed, true);
  return reserved.state;
}

export function withCurrentReviewLease(state, now = NOW + 10) {
  if (state.activeWorker?.kind === "review") {
    return state;
  }
  if (state.reviewLease?.kind === "review" && state.reviewLease.headSha === state.headSha) {
    return state;
  }
  return reserve(state, "review", "agent:owner-agent:subagent:mprl-flow-0-review", now);
}

export function applyCurrentReview(state, overrides = {}, now = NOW + 20) {
  const leased = withCurrentReviewLease(state);
  const lease = leased.activeWorker?.kind === "review" ? leased.activeWorker : leased.reviewLease;
  return applyReviewResult(
    leased,
    reviewResult({
      claimRef: lease?.claimRef,
      reviewId: lease?.reviewId ?? "9000000001",
      ...overrides,
    }),
    now,
  );
}

export function attachWorkerIdentity(state, suffix, flowId = "flow-controller-test") {
  return {
    ...state,
    activeWorker: {
      ...state.activeWorker,
      flowId,
      runId: `run-${suffix}`,
      taskId: `task-${suffix}`,
    },
  };
}
