import { createHash, randomUUID } from "node:crypto";
import { PHASE, isSha, mergeAuthorizationAllows } from "./controller.mjs";
import {
  BROKER_CALL_TIMEOUT_MS,
  DEFAULT_BROKER_COMMAND,
  MERGE_LOCK_NAMESPACE,
  MERGE_LOCK_TTL_MS,
  execFile,
  mergeLockStores,
} from "./runtime-foundation.mjs";

export async function readWorkspaceHead(api, workspace, expectedHeadSha) {
  if (typeof api.__testReadWorkspaceHead === "function") {
    return await api.__testReadWorkspaceHead(workspace, expectedHeadSha);
  }
  const { stdout: status } = await execFile(
    "git",
    [
      "-C",
      workspace,
      "status",
      "--porcelain=v1",
      "--untracked-files=all",
      "--ignore-submodules=none",
    ],
    {
      encoding: "utf8",
      maxBuffer: 64 * 1024,
      timeout: 10_000,
      windowsHide: true,
    },
  );
  if (status.trim()) {
    throw new Error("workspace_dirty");
  }
  const { stdout } = await execFile("git", ["-C", workspace, "rev-parse", "--verify", "HEAD"], {
    encoding: "utf8",
    maxBuffer: 4_096,
    timeout: 10_000,
    windowsHide: true,
  });
  const headSha = stdout.trim().toLowerCase();
  if (!/^[0-9a-f]{40}$/.test(headSha)) {
    throw new Error("workspace_head_not_full_sha");
  }
  return headSha;
}

export function reconciliationTimestamp(state) {
  const timestamp = state.pendingGithubReconciliation?.githubUpdatedAt ?? state.githubUpdatedAt;
  if (!Number.isSafeInteger(timestamp)) {
    throw new Error("github_reconciliation_timestamp_missing");
  }
  return new Date(timestamp).toISOString();
}

export function brokerRepoAlias(policy) {
  const alias = policy?.brokerRepoAlias;
  if (typeof alias !== "string" || !/^[A-Za-z0-9_.-]+$/.test(alias)) {
    throw new Error("broker_repo_alias_invalid");
  }
  return alias;
}

export function normalizeAuthoritativePullRequest(state, payload) {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    throw new Error("github_reconciliation_payload_invalid");
  }
  const head = payload.head;
  const base = payload.base;
  const repo = typeof payload.repo === "string" ? payload.repo : state.repo;
  const prNumber = Number(payload.number ?? payload.prNumber);
  const headRepo = head?.repo ?? head?.repository;
  const baseRef = base?.ref;
  const headSha = head?.sha ?? payload.headSha;
  const baseSha = base?.sha ?? payload.baseSha;
  if (
    repo !== state.repo ||
    prNumber !== state.prNumber ||
    typeof headRepo !== "string" ||
    typeof baseRef !== "string" ||
    typeof headSha !== "string" ||
    typeof baseSha !== "string" ||
    !isSha(headSha.toLowerCase()) ||
    !isSha(baseSha.toLowerCase())
  ) {
    throw new Error("github_reconciliation_payload_mismatch");
  }
  return {
    eventId: `github:reconcile:${state.prNumber}:${state.updatedAt}:${headSha.toLowerCase()}`.slice(
      0,
      160,
    ),
    action: "synchronize",
    repo,
    prNumber,
    headSha: headSha.toLowerCase(),
    baseSha: baseSha.toLowerCase(),
    baseRef,
    headRepo,
    updatedAt: reconciliationTimestamp(state),
    authoritative: true,
  };
}

export async function readAuthoritativePullRequest(api, config, state) {
  if (typeof api.__testReadPullRequestState === "function") {
    return normalizeAuthoritativePullRequest(
      state,
      await api.__testReadPullRequestState(structuredClone(state)),
    );
  }
  const policy = config.repositories.get(state.repo);
  if (!policy) {
    throw new Error("github_reconciliation_repository_policy_missing");
  }
  const { stdout } = await execFile(
    config.repositoryBrokerPath,
    ["pr-state", brokerRepoAlias(policy), String(state.prNumber), "--json"],
    {
      encoding: "utf8",
      maxBuffer: 256 * 1024,
      timeout: 90_000,
      windowsHide: true,
    },
  );
  let payload;
  try {
    payload = JSON.parse(stdout);
  } catch {
    throw new Error("github_reconciliation_invalid_json");
  }
  return normalizeAuthoritativePullRequest(state, payload);
}

export async function runBroker(api, args, config = {}) {
  if (typeof api.testRunBroker === "function") {
    return await api.testRunBroker(args);
  }
  const { stdout } = await execFile(config.repositoryBrokerPath ?? DEFAULT_BROKER_COMMAND, args, {
    encoding: "utf8",
    maxBuffer: 1024 * 1024,
    timeout: BROKER_CALL_TIMEOUT_MS,
    windowsHide: true,
  });
  let payload;
  try {
    payload = JSON.parse(stdout);
  } catch {
    throw new Error("broker_returned_invalid_json");
  }
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    throw new Error("broker_returned_invalid_payload");
  }
  return payload;
}

export function mergeLockStore(api) {
  const existing = mergeLockStores.get(api);
  if (existing) {
    return existing;
  }
  const openStore = api.runtime?.state?.openSyncKeyedStore;
  if (typeof openStore !== "function") {
    throw new Error("merge_lock_store_unavailable");
  }
  const store = openStore({
    namespace: MERGE_LOCK_NAMESPACE,
    maxEntries: 128,
    overflowPolicy: "reject-new",
  });
  if (
    !store ||
    typeof store.registerIfAbsent !== "function" ||
    typeof store.update !== "function" ||
    typeof store.deleteIf !== "function"
  ) {
    throw new Error("merge_lock_store_is_not_atomic");
  }
  mergeLockStores.set(api, store);
  return store;
}

export function acquireMergeLock(api, flow, state, now = Date.now()) {
  if (typeof api.testAcquireMergeLock === "function") {
    return api.testAcquireMergeLock(flow, state, now);
  }
  const store = mergeLockStore(api);
  const key = `merge:${createHash("sha256")
    .update(`${state.repo}:${state.baseRef}`)
    .digest("hex")}`;
  const token = randomUUID();
  const acquired = store.registerIfAbsent(
    key,
    {
      schemaVersion: 1,
      token,
      flowId: flow.flowId,
      repository: state.repo,
      baseRef: state.baseRef,
      headSha: state.headSha,
      acquiredAt: now,
    },
    { ttlMs: MERGE_LOCK_TTL_MS },
  );
  if (!acquired) {
    return null;
  }
  let released = false;
  return {
    key,
    token,
    assertAndRenew(renewedAt = Date.now()) {
      if (released) {
        return false;
      }
      return store.update(
        key,
        (current) =>
          current?.token === token
            ? {
                ...current,
                renewedAt,
              }
            : undefined,
        { ttlMs: MERGE_LOCK_TTL_MS },
      );
    },
    release() {
      if (released) {
        return false;
      }
      released = true;
      return store.deleteIf(key, (current) => current?.token === token);
    },
  };
}

export class AutoMergeGateError extends Error {
  constructor(diagnostics) {
    const failed = Object.entries(diagnostics.gates)
      .filter(([, gate]) => gate.ready !== true)
      .map(([name]) => name);
    super(`automatic_merge_gates_not_satisfied:${failed.join(",")}`);
    this.name = "AutoMergeGateError";
    this.diagnostics = diagnostics;
    this.waitForEvent = diagnostics.waitForEvent === true;
  }
}

export class AutoMergeRevisionChangedError extends Error {
  constructor(currentFlow) {
    super("automatic_merge_revision_changed");
    this.name = "AutoMergeRevisionChangedError";
    this.currentFlow = currentFlow ?? null;
  }
}

export function checkRunView(run) {
  return {
    name: typeof run?.name === "string" ? run.name.slice(0, 200) : "unknown",
    status: typeof run?.status === "string" ? run.status.slice(0, 40) : "unknown",
    conclusion:
      typeof run?.conclusion === "string" ? run.conclusion.slice(0, 40) : (run?.conclusion ?? null),
    app: typeof run?.app === "string" ? run.app.slice(0, 200) : null,
    url:
      typeof run?.details_url === "string"
        ? run.details_url.slice(0, 1000)
        : typeof run?.html_url === "string"
          ? run.html_url.slice(0, 1000)
          : null,
  };
}

export function mergeGateDiagnostics(state, remote, now = Date.now()) {
  const checkRuns = Array.isArray(remote?.checks?.check_runs)
    ? remote.checks.check_runs.map(checkRunView)
    : [];
  const failedChecks = checkRuns.filter(
    (run) =>
      run.status === "completed" && !new Set(["success", "neutral", "skipped"]).has(run.conclusion),
  );
  const pendingChecks = checkRuns.filter((run) => run.status !== "completed");
  const brokerRuns = checkRuns.filter((run) => run.name === "Broker review");
  const review = remote?.reviewers?.broker_review;
  const authorizationReady =
    mergeAuthorizationAllows(state, now) &&
    state.mergeReady?.authorizationDigest === state.mergeAuthorization?.digest;
  const gates = {
    authorization: {
      ready: authorizationReady,
      authorizationId: state.mergeAuthorization?.authorizationId ?? null,
      digest: state.mergeAuthorization?.digest ?? null,
      expiresAt: state.mergeAuthorization?.expiresAt ?? null,
      revokedAt: state.mergeAuthorization?.revokedAt ?? null,
      supersededBy: state.mergeAuthorization?.supersededBy ?? null,
    },
    remoteIdentity: {
      ready:
        remote?.head?.sha === state.headSha &&
        remote?.head?.repo === state.repo &&
        remote?.base?.ref === state.baseRef &&
        remote?.base?.sha === state.baseSha,
      expected: {
        repository: state.repo,
        headSha: state.headSha,
        baseRef: state.baseRef,
        baseSha: state.baseSha,
      },
      observed: {
        repository: remote?.head?.repo ?? null,
        headSha: remote?.head?.sha ?? null,
        baseRef: remote?.base?.ref ?? null,
        baseSha: remote?.base?.sha ?? null,
      },
    },
    pullRequestState: { ready: remote?.state === "open", observed: remote?.state ?? null },
    draft: { ready: remote?.draft === false, observed: remote?.draft ?? null },
    mergeability: {
      ready: remote?.mergeable === true,
      observed: remote?.mergeable ?? null,
    },
    requiredChecks: {
      ready: remote?.checks?.ready === true,
      failed: remote?.checks?.ready === true ? [] : failedChecks,
      pending: remote?.checks?.ready === true ? [] : pendingChecks,
      all: checkRuns,
    },
    brokerCheck: {
      ready: brokerRuns.some(
        (run) => run.app === "broker" && run.status === "completed" && run.conclusion === "success",
      ),
      runs: brokerRuns,
    },
    exactReview: {
      ready:
        ["approved", "passed", "success"].includes(review?.status) &&
        review?.coverage_complete === true &&
        review?.reviewed_head_sha === state.headSha &&
        review?.reviewed_base_sha === state.baseSha,
      reviewId: review?.review_id ?? state.review?.reviewId ?? null,
      reviewedHeadSha: review?.reviewed_head_sha ?? null,
      reviewedBaseSha: review?.reviewed_base_sha ?? null,
      coverageComplete: review?.coverage_complete === true,
    },
    findings: {
      ready: Number(review?.findings_count) === 0 && Number(review?.blocking_findings_count) === 0,
      findingsCount: Number.isFinite(Number(review?.findings_count))
        ? Number(review.findings_count)
        : null,
      blockingFindingsCount: Number.isFinite(Number(review?.blocking_findings_count))
        ? Number(review.blocking_findings_count)
        : null,
    },
  };
  const ready = Object.values(gates).every((gate) => gate.ready === true);
  const hardGateFailed =
    !gates.authorization.ready ||
    !gates.remoteIdentity.ready ||
    !gates.pullRequestState.ready ||
    !gates.draft.ready ||
    !gates.exactReview.ready ||
    !gates.findings.ready ||
    remote?.mergeable === false;
  return {
    schemaVersion: 1,
    headSha: state.headSha,
    baseSha: state.baseSha,
    baseRef: state.baseRef,
    observedAt: now,
    ready,
    waitForEvent: !ready && !hardGateFailed,
    gates,
  };
}

export function requireAutoMergePolicy(state, policy, now = Date.now()) {
  if (
    state.phase !== PHASE.MERGE_QUEUED ||
    state.mode !== "active" ||
    state.autoMergeMethod !== "merge" ||
    !Array.isArray(state.autoMergeBaseBranches) ||
    !state.autoMergeBaseBranches.includes(state.baseRef) ||
    state.mergeReady?.mergeAuthorized !== true ||
    !mergeAuthorizationAllows(state, now) ||
    state.mergeReady?.authorizationDigest !== state.mergeAuthorization?.digest ||
    policy?.mergeAuthorization?.digest !== state.mergeAuthorization?.digest ||
    policy?.mergePolicyDigest !== state.mergePolicyDigest ||
    policy?.brokerRepoAlias !== state.brokerRepoAlias ||
    state.mergeAuthorization?.policyDigest !== state.mergePolicyDigest ||
    policy?.autoMergeMethod !== "merge" ||
    policy?.autoMergeMethod !== state.autoMergeMethod ||
    typeof policy?.mergeActor !== "string" ||
    !policy.mergeActor ||
    !policy?.autoMergeBaseBranches?.includes(state.baseRef)
  ) {
    throw new AutoMergeGateError({
      schemaVersion: 1,
      headSha: state.headSha,
      baseSha: state.baseSha,
      baseRef: state.baseRef,
      observedAt: now,
      ready: false,
      waitForEvent: false,
      gates: {
        authorization: {
          ready: false,
          authorizationId: state.mergeAuthorization?.authorizationId ?? null,
          digest: state.mergeAuthorization?.digest ?? null,
          expiresAt: state.mergeAuthorization?.expiresAt ?? null,
          revokedAt: state.mergeAuthorization?.revokedAt ?? null,
          supersededBy: state.mergeAuthorization?.supersededBy ?? null,
        },
      },
    });
  }
}
