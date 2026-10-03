import { execFile as execFileCallback } from "node:child_process";
import { createHash } from "node:crypto";
import { chmodSync, lstatSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import {
  CONTROLLER_ID,
  PHASE,
  applyPullRequestEvent,
  applyReviewResult,
  applyWorkerFailure,
  applyWorkerReport,
  attachWorkerRun,
  blockState,
  classifyWorkerFailure,
  createState,
  flowMatches,
  isLifecycleState,
  isTerminalState,
  normalizePolicy,
  normalizePullRequestEvent,
  recoverState,
  refreshPolicySnapshot,
  reserveWorker,
  workerKindForPhase,
} from "./controller.mjs";
import {
  createFixedWindowLimiter,
  createInFlightLimiter,
  mapHttpError,
  parseGitHubPullRequest,
  parseMergeguezReviewEvent,
  readJsonBody,
  requestKey,
  requireJsonPost,
  verifySha256Signature,
  writeJson,
} from "./http.mjs";

const TOOL_NAME = "mergeguez_pr_lifecycle";
const TERMINAL_FLOW_STATUSES = new Set(["succeeded", "failed", "cancelled", "lost"]);
const RUNTIME_SOURCE_PATH = fileURLToPath(import.meta.url);
const REMEDIATION_COMMAND = "/home/node/.openclaw/bin/le-commis-taskflow-remediate";
const MERGEGUEZ_COMMAND = "/home/node/.openclaw/bin/mergeguez";
const AUTO_MERGE_ACTOR = "mergeguez[bot]";
const REMEDIATION_ROOT = "/home/node/.openclaw/taskflow-remediation";
const execFile = promisify(execFileCallback);

const bindingCleanupEvidence = new WeakMap();
function cleanupFailureCode(error) {
  return typeof error?.code === "string" && /^[A-Za-z0-9_.:-]{1,80}$/.test(error.code)
    ? error.code
    : "task_binding_close_failed";
}
async function closeTaskBindings(api, bindings, primary) {
  const failures = [];
  for (const binding of new Set(bindings.filter(Boolean))) {
    try {
      await binding.close();
    } catch (error) {
      if (failures.length < 8) failures.push(cleanupFailureCode(error));
    }
  }
  if (!failures.length) return;
  const evidence = Object.freeze(failures);
  if (primary) {
    if (
      primary.error &&
      (typeof primary.error === "object" || typeof primary.error === "function")
    ) {
      bindingCleanupEvidence.set(primary.error, evidence);
    }
    try {
      api.logger?.error?.(`Publisher binding cleanup failed: ${JSON.stringify(evidence)}`);
    } catch {}
    return; // Preserve the exact primary native outcome/error, including frozen errors.
  }
  const failure = new Error("Publisher task binding cleanup did not complete");
  failure.code = "task_binding_close_failed";
  bindingCleanupEvidence.set(failure, evidence);
  throw failure;
}
async function withTaskBindingClosure(api, bindings, operation) {
  let primary;
  try {
    return await operation();
  } catch (error) {
    primary = { error };
    throw error;
  } finally {
    await closeTaskBindings(api, bindings, primary);
  }
}
function captureCapacitySnapshot(value) {
  const captured = structuredClone(value);
  captured.ownerSessionKeys = Object.freeze([...captured.ownerSessionKeys]);
  captured.snapshot = Object.freeze(
    captured.snapshot.map((entry) =>
      Object.freeze({
        flowId: entry.flowId,
        ownerKey: entry.ownerKey,
        revision: entry.revision,
      }),
    ),
  );
  captured.flows = Object.freeze([...captured.flows]);
  return Object.freeze(captured);
}
function recoverObservedState(state, workerTask, now, grace, extras) {
  if (state?.activeWorker && state.launchOutcome?.status === "unknown" && !workerTask) {
    return { changed: false, state, effect: "hold", reason: "worker_launch_outcome_unknown" };
  }
  if (
    ["native-subagent", "legacy-task"].includes(workerTask?.observationSource) &&
    workerTask.status === "unknown"
  ) {
    return {
      changed: false,
      state,
      effect: "hold",
      reason:
        workerTask.observationSource === "native-subagent"
          ? "native_worker_outcome_unknown"
          : "legacy_worker_outcome_unknown",
    };
  }
  return recoverState(state, workerTask, now, grace, extras);
}

const INSTALLED_COMPATIBLE_RUNTIME_SHA256 =
  "7e6cbe8ab75213049fc21f85dc5df4b2c740ac9cfd35edd1d4aadc4a92167e74";

// Release/Doctor owns applying this proposal and binding the new exact artifact.
// This pure helper neither writes config nor grants activation authority.
export function proposeInstalledPublisherRuntimePinMigration(config, transition) {
  const expectedPath = config?.expectedRuntimePath;
  const expectedSha256 = config?.expectedRuntimeSha256;
  const fromPath = transition?.fromPath;
  const fromSha256 = transition?.fromSha256;
  const toSha256 = transition?.toSha256;
  if (
    typeof expectedPath !== "string" ||
    !expectedPath.trim() ||
    expectedPath !== fromPath ||
    transition?.toPath !== expectedPath
  ) {
    throw new Error("publisher_runtime_pin_path_preimage_mismatch");
  }
  if (expectedSha256 !== INSTALLED_COMPATIBLE_RUNTIME_SHA256 || fromSha256 !== expectedSha256) {
    throw new Error("publisher_runtime_pin_hash_preimage_mismatch");
  }
  if (
    typeof toSha256 !== "string" ||
    !/^[a-f0-9]{64}$/.test(toSha256) ||
    toSha256 === expectedSha256
  ) {
    throw new Error("publisher_runtime_pin_successor_invalid");
  }
  return Object.freeze({
    kind: "exact-preimage-runtime-pin-proposal",
    applied: false,
    requiresPluginOwnedDoctorRelease: true,
    precondition: Object.freeze({
      expectedRuntimePath: expectedPath,
      expectedRuntimeSha256: expectedSha256,
    }),
    patch: Object.freeze({ expectedRuntimePath: expectedPath, expectedRuntimeSha256: toSha256 }),
  });
}

function remediationRoot(api) {
  return typeof api.testRemediationRoot === "string" && api.testRemediationRoot
    ? api.testRemediationRoot
    : REMEDIATION_ROOT;
}

function remediationJobId(flow, state) {
  const token = flow.flowId.replace(/[^a-zA-Z0-9]/g, "").slice(0, 16);
  return (
    `mprl-${token}-c${state.cycle}-g${workerGenerationForState(state)}-` +
    `r${state.retryCount ?? 0}-i${state.infrastructureRetryCount ?? 0}`
  );
}

function remediationJobBinding(flow, state, policy, jobId) {
  return {
    schemaVersion: 1,
    jobId,
    flowId: flow.flowId,
    flowRevision: flow.revision,
    repo: state.repo,
    prNumber: state.prNumber,
    headSha: state.headSha,
    baseSha: state.baseSha,
    baseRef: state.baseRef,
    cycle: state.cycle,
    workerGeneration: workerGenerationForState(state),
    retryCount: state.retryCount ?? 0,
    infrastructureRetryCount: state.infrastructureRetryCount ?? 0,
    workspace: flowWorkspacePath(policy, state),
    fixerModel: state.fixerModel,
    fixerFallbackModel: state.fixerFallbackModel,
    publisherBrokerId: state.publisherBoundary?.brokerId ?? null,
    publisherAttestationRef: state.publisherBoundary?.attestationRef ?? null,
    findings: state.findings ?? [],
  };
}

function prepareRemediationJob(api, flow, state, policy) {
  const jobId = remediationJobId(flow, state);
  const binding = remediationJobBinding(flow, state, policy, jobId);
  const bindingJson = `${JSON.stringify(binding, null, 2)}\n`;
  const bindingSha256 = createHash("sha256").update(bindingJson).digest("hex");
  if (typeof api.testPrepareRemediationJob === "function") {
    return api.testPrepareRemediationJob({ jobId, binding, bindingJson, bindingSha256 });
  }
  const jobsRoot = join(remediationRoot(api), "jobs");
  const jobDir = join(jobsRoot, jobId);
  mkdirSync(jobsRoot, { recursive: true, mode: 0o700 });
  mkdirSync(jobDir, { recursive: false, mode: 0o700 });
  const prompt = [
    "You are Cursor acting only as a bounded local code fixer.",
    `Immutable remediation binding: ${JSON.stringify(binding)}`,
    "Fix every listed finding with the smallest correct change.",
    "Do not use git, GitHub, network publishing, review actions, merge actions, or credentials.",
    "Do not create a .git path. Edit only finding paths and narrowly related regression tests.",
    "The separate Le Commis host broker will validate, commit, and publish after you exit.",
  ].join("\n");
  const acceptance = [
    `The exact starting head remains ${state.headSha}.`,
    "Every finding is fixed and has focused regression coverage.",
    "No unrelated file is changed and no Git metadata is created.",
  ].join("\n");
  writeFileSync(join(jobDir, "binding.json"), bindingJson, {
    encoding: "utf8",
    mode: 0o600,
    flag: "wx",
  });
  writeFileSync(join(jobDir, "prompt.md"), `${prompt}\n`, {
    encoding: "utf8",
    mode: 0o600,
    flag: "wx",
  });
  writeFileSync(join(jobDir, "acceptance.md"), `${acceptance}\n`, {
    encoding: "utf8",
    mode: 0o600,
    flag: "wx",
  });
  chmodSync(jobDir, 0o700);
  return { jobId, bindingSha256 };
}

function verifyRemediationEvidence(api, state, input) {
  if (typeof api.testVerifyRemediationEvidence === "function") {
    return api.testVerifyRemediationEvidence(state, input);
  }
  const job = state?.activeWorker?.remediationJob;
  if (!job?.jobId || !/^[A-Za-z0-9._-]+$/.test(job.jobId)) {
    throw new Error("remediation_job_binding_missing");
  }
  const evidencePath = join(remediationRoot(api), "runs", job.jobId, "evidence.json");
  const stat = lstatSync(evidencePath);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size < 2 || stat.size > 32_768) {
    throw new Error("remediation_evidence_file_invalid");
  }
  const raw = readFileSync(evidencePath, "utf8");
  const digest = createHash("sha256").update(raw).digest("hex");
  const evidence = JSON.parse(raw);
  if (
    input.fixerAttestationRef !== `sha256:${digest}` ||
    evidence.schemaVersion !== 1 ||
    evidence.status !== input.outcome ||
    evidence.jobId !== job.jobId ||
    evidence.bindingSha256 !== job.bindingSha256 ||
    evidence.repo !== state.repo ||
    evidence.prNumber !== state.prNumber ||
    evidence.previousHeadSha !== state.headSha ||
    evidence.newHeadSha !== input.newHeadSha ||
    evidence.cycle !== state.cycle ||
    evidence.testsPassed !== true ||
    evidence.publicationConfirmed !== true ||
    evidence.fixerModel !== input.fixerModel ||
    evidence.fixerAttested !== true
  ) {
    throw new Error("remediation_evidence_mismatch");
  }
  return true;
}

function remediationReportFromEvidence(api, state) {
  if (state?.activeWorker?.kind !== "remediation") {
    return null;
  }
  if (typeof api.testReadRemediationEvidence === "function") {
    const input = api.testReadRemediationEvidence(state);
    if (!input) {
      return null;
    }
    verifyRemediationEvidence(api, state, input);
    return input;
  }
  const job = state.activeWorker.remediationJob;
  if (!job?.jobId || !/^[A-Za-z0-9._-]+$/.test(job.jobId)) {
    return null;
  }
  const evidencePath = join(remediationRoot(api), "runs", job.jobId, "evidence.json");
  let stat;
  try {
    stat = lstatSync(evidencePath);
  } catch (error) {
    if (error && typeof error === "object" && error.code === "ENOENT") {
      return null;
    }
    throw error;
  }
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size < 2 || stat.size > 32_768) {
    throw new Error("remediation_evidence_file_invalid");
  }
  const raw = readFileSync(evidencePath, "utf8");
  const evidence = JSON.parse(raw);
  const input = {
    action: "report",
    kind: "remediation",
    outcome: evidence.status,
    headSha: state.headSha,
    cycle: state.cycle,
    newHeadSha: evidence.newHeadSha,
    testsPassed: evidence.testsPassed,
    publicationConfirmed: evidence.publicationConfirmed,
    fixerModel: evidence.fixerModel,
    fixerAttested: evidence.fixerAttested,
    fixerAttestationRef: `sha256:${createHash("sha256").update(raw).digest("hex")}`,
  };
  verifyRemediationEvidence(api, state, input);
  return input;
}

async function reconcileRemediationEvidence(api, config, boundFlows, flow) {
  const state = stateOf(flow);
  if (!state || state.activeWorker?.kind !== "remediation") {
    return { changed: false, flow, reason: "no_active_remediation" };
  }
  let input;
  try {
    input = remediationReportFromEvidence(api, state);
  } catch (error) {
    const detail = error instanceof Error ? error.message : "unknown";
    const blocked = blockState(state, `remediation_evidence_invalid:${detail.slice(0, 240)}`);
    const blockedFlow = requireApplied(await persistState(boundFlows, flow, blocked.state));
    await applyEffect(api, config, boundFlows, blockedFlow, blocked.state, blocked.effect);
    return { changed: true, flow: blockedFlow, reason: "remediation_evidence_invalid" };
  }
  if (!input) {
    return { changed: false, flow, reason: "remediation_evidence_missing" };
  }
  const transition = applyWorkerReport(state, input, state.activeWorker.sessionKey);
  let nextState = transition.state;
  let nextEffect = transition.effect;
  let nextFlow = requireApplied(await persistState(boundFlows, flow, nextState));
  const gate = enforceModeGate(nextState);
  if (gate.changed) {
    nextState = gate.state;
    nextEffect = gate.effect;
    nextFlow = requireApplied(await persistState(boundFlows, nextFlow, nextState));
  }
  await applyEffect(api, config, boundFlows, nextFlow, nextState, nextEffect, {
    dispatchImmediately: true,
  });
  nextFlow = (await boundFlows.get(nextFlow.flowId)) ?? nextFlow;
  return { changed: true, flow: nextFlow, reason: "remediation_evidence_reconciled" };
}

function isDisposableRuntimePath(value) {
  const normalizedPath = typeof value === "string" ? value.replaceAll("\\", "/") : "";
  return (
    normalizedPath.includes("/.openclaw/tmp/") ||
    normalizedPath.includes("/.openclaw/worktrees/") ||
    normalizedPath.startsWith("/tmp/")
  );
}

function runtimeSourceIntegrity(expectedPath, expectedSha256, options = {}) {
  const actualSha256 = createHash("sha256").update(readFileSync(RUNTIME_SOURCE_PATH)).digest("hex");
  const durable = !isDisposableRuntimePath(RUNTIME_SOURCE_PATH);
  return {
    path: RUNTIME_SOURCE_PATH,
    sha256: actualSha256,
    durable,
    verified:
      typeof expectedPath === "string" &&
      expectedPath === RUNTIME_SOURCE_PATH &&
      typeof expectedSha256 === "string" &&
      expectedSha256 === actualSha256 &&
      (durable || options.allowDisposable === true),
  };
}

async function readWorkspaceHead(api, workspace, expectedHeadSha) {
  if (typeof api.testReadWorkspaceHead === "function") {
    return await api.testReadWorkspaceHead(workspace, expectedHeadSha);
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

async function runMergeguez(api, args) {
  if (typeof api.testRunMergeguez === "function") {
    return await api.testRunMergeguez(args);
  }
  const { stdout } = await execFile(MERGEGUEZ_COMMAND, args, {
    encoding: "utf8",
    maxBuffer: 1024 * 1024,
    timeout: 60_000,
    windowsHide: true,
  });
  let payload;
  try {
    payload = JSON.parse(stdout);
  } catch {
    throw new Error("mergeguez_returned_invalid_json");
  }
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    throw new Error("mergeguez_returned_invalid_payload");
  }
  return payload;
}

function requireAutoMergePolicy(state) {
  if (
    state.phase !== PHASE.MERGE_QUEUED ||
    state.mode !== "active" ||
    state.baseRef !== "dev" ||
    !Array.isArray(state.autoMergeBaseBranches) ||
    !state.autoMergeBaseBranches.includes("dev") ||
    state.mergeReady?.mergeAuthorized !== true
  ) {
    throw new Error("automatic_merge_not_authorized");
  }
}

function mergedState(state, receipt, now = Date.now()) {
  return {
    ...state,
    phase: PHASE.MERGED,
    activeWorker: null,
    wait: null,
    blocker: null,
    merged: {
      headSha: state.headSha,
      baseRef: state.baseRef,
      mergeMethod: state.autoMergeMethod ?? "merge",
      actor: AUTO_MERGE_ACTOR,
      receipt,
      mergedAt: now,
    },
    updatedAt: now,
  };
}

async function autoMergeReceipt(api, state) {
  requireAutoMergePolicy(state);
  const alias = state.repo.split("/").at(-1);
  const remote = await runMergeguez(api, [
    "pr-state",
    alias,
    String(state.prNumber),
    "--expected-sha",
    state.headSha,
    "--json",
  ]);
  if (
    remote.head?.sha !== state.headSha ||
    remote.head?.repo !== state.repo ||
    remote.base?.ref !== "dev"
  ) {
    throw new Error("automatic_merge_remote_identity_mismatch");
  }
  if (remote.merged === true) {
    if (remote.merged_by?.login !== AUTO_MERGE_ACTOR) {
      throw new Error("automatic_merge_reconciliation_actor_mismatch");
    }
    return { ...remote, reconciledAlreadyMerged: true };
  }
  const review = remote.reviewers?.mergeguez_review;
  const checkRuns = Array.isArray(remote.checks?.check_runs) ? remote.checks.check_runs : [];
  const mergeguezCheckReady = checkRuns.some(
    (run) =>
      run?.name === "Mergeguez review" &&
      run?.status === "completed" &&
      run?.conclusion === "success",
  );
  const readyReview =
    ["approved", "passed", "success"].includes(review?.status) &&
    review?.coverage_complete === true &&
    review?.reviewed_head_sha === state.headSha &&
    review?.reviewed_base_sha === state.baseSha &&
    Number(review?.findings_count) === 0 &&
    Number(review?.blocking_findings_count) === 0;
  if (
    remote.state !== "open" ||
    remote.draft === true ||
    remote.mergeable !== true ||
    remote.checks?.ready !== true ||
    !mergeguezCheckReady ||
    !readyReview
  ) {
    throw new Error("automatic_merge_gates_not_satisfied");
  }
  const headRef = remote.head?.ref;
  if (typeof headRef !== "string" || !headRef.trim()) {
    throw new Error("automatic_merge_head_ref_missing");
  }
  const receipt = await runMergeguez(api, [
    "merge-pr",
    alias,
    String(state.prNumber),
    "--expected-base",
    "dev",
    "--expected-head-branch",
    headRef,
    "--expected-head-sha",
    state.headSha,
    "--expected-actor-login",
    AUTO_MERGE_ACTOR,
    "--merge-method",
    state.autoMergeMethod ?? "merge",
    "--json",
  ]);
  if (
    receipt.merged !== true ||
    receipt.base !== "dev" ||
    receipt.head_sha !== state.headSha ||
    receipt.actor_verification !== "passed"
  ) {
    throw new Error("automatic_merge_receipt_invalid");
  }
  return receipt;
}

function result(value) {
  return {
    content: [{ type: "text", text: JSON.stringify(value) }],
    details: value,
  };
}

function normalizePath(value, fallback) {
  const candidate = typeof value === "string" && value.trim() ? value.trim() : fallback;
  if (!candidate.startsWith("/") || candidate.includes("?") || candidate.includes("#")) {
    throw new Error("webhook path must be an absolute path without query or fragment");
  }
  return candidate.replace(/\/+$/, "") || "/";
}

function normalizeStringArray(value, field, maxItems = 32) {
  if (value === undefined || value === null) {
    return [];
  }
  if (!Array.isArray(value) || value.length > maxItems) {
    throw new Error(`${field} must be an array with at most ${maxItems} entries`);
  }
  const normalized = value.map((item) => {
    if (typeof item !== "string" || !item.trim() || item.trim().length > 500) {
      throw new Error(`${field} contains an invalid entry`);
    }
    return item.trim();
  });
  return [...new Set(normalized)];
}

function normalizeRuntimeConfig(input = {}) {
  const maxParallelPrs =
    Number.isInteger(input.maxParallelPrs) &&
    input.maxParallelPrs >= 1 &&
    input.maxParallelPrs <= 16
      ? input.maxParallelPrs
      : 1;
  const maxParallelPrsGlobal =
    Number.isInteger(input.maxParallelPrsGlobal) &&
    input.maxParallelPrsGlobal >= 1 &&
    input.maxParallelPrsGlobal <= 32
      ? input.maxParallelPrsGlobal
      : null;
  const repositories = new Map();
  for (const [repo, policyInput] of Object.entries(input.repositories ?? {})) {
    repositories.set(
      repo,
      normalizePolicy({
        ...policyInput,
        maxParallelPrs: Number.isInteger(policyInput?.maxParallelPrs)
          ? policyInput.maxParallelPrs
          : maxParallelPrs,
      }),
    );
  }
  const githubWebhookPath = normalizePath(
    input.githubWebhookPath,
    "/plugins/mergeguez-pr-lifecycle/github",
  );
  const mergeguezEventPath = normalizePath(
    input.mergeguezEventPath,
    "/plugins/mergeguez-pr-lifecycle/mergeguez",
  );
  if (githubWebhookPath === mergeguezEventPath) {
    throw new Error("GitHub and Mergeguez event paths must be distinct");
  }
  return {
    enabled: input.enabled === true,
    ownerSessionKey:
      typeof input.ownerSessionKey === "string" && input.ownerSessionKey.trim()
        ? input.ownerSessionKey.trim()
        : null,
    notificationSessionKey:
      typeof input.notificationSessionKey === "string" && input.notificationSessionKey.trim()
        ? input.notificationSessionKey.trim()
        : null,
    legacyOwnerSessionKeys: normalizeStringArray(
      input.legacyOwnerSessionKeys,
      "legacyOwnerSessionKeys",
    ),
    statusAgentIds: normalizeStringArray(input.statusAgentIds, "statusAgentIds").map((value) => {
      if (!/^[A-Za-z0-9_.-]+$/.test(value)) {
        throw new Error("statusAgentIds contains an invalid agent id");
      }
      return value;
    }),
    expectedRuntimePath:
      typeof input.expectedRuntimePath === "string" && input.expectedRuntimePath.trim()
        ? input.expectedRuntimePath.trim()
        : null,
    expectedRuntimeSha256:
      typeof input.expectedRuntimeSha256 === "string" &&
      /^[0-9a-f]{64}$/.test(input.expectedRuntimeSha256)
        ? input.expectedRuntimeSha256
        : null,
    githubWebhookPath,
    mergeguezEventPath,
    githubWebhookSecret:
      typeof input.githubWebhookSecret === "string" ? input.githubWebhookSecret : null,
    mergeguezEventSecret:
      typeof input.mergeguezEventSecret === "string" ? input.mergeguezEventSecret : null,
    recoveryDelayMinutes:
      Number.isInteger(input.recoveryDelayMinutes) && input.recoveryDelayMinutes >= 5
        ? input.recoveryDelayMinutes
        : 5,
    maxParallelPrs,
    maxParallelPrsGlobal,
    repositories,
  };
}

async function bindFlowsForSession(api, sessionKey) {
  const bound = await api.runtime.tasks.managedFlows.bindSession({ sessionKey });
  const required = [
    "get",
    "list",
    "createManaged",
    "finish",
    "fail",
    "setWaiting",
    "resume",
    "capacitySnapshot",
    "reserve",
    "assertCurrent",
    "close",
  ];
  if (required.some((name) => typeof bound?.[name] !== "function")) {
    const primary = { error: new Error("publisher_flow_parity_port_unavailable") };
    if (typeof bound?.close === "function") await closeTaskBindings(api, [bound], primary);
    throw primary.error;
  }
  return bound;
}

function ownerSessionKeyForRepo(config, repo) {
  if (!repo) {
    return config.ownerSessionKey;
  }
  const policy = config.repositories.get(repo);
  if (policy?.ownerSessionKey) {
    return policy.ownerSessionKey;
  }
  return config.ownerSessionKey;
}

function uniqueOwnerSessionKeys(config) {
  const keys = [];
  const seen = new Set();
  const add = (value) => {
    if (typeof value === "string" && value && !seen.has(value)) {
      seen.add(value);
      keys.push(value);
    }
  };
  add(config.ownerSessionKey);
  for (const sessionKey of config.legacyOwnerSessionKeys) {
    add(sessionKey);
  }
  for (const policy of config.repositories.values()) {
    add(policy.ownerSessionKey);
  }
  return keys;
}

async function collectLifecycleFlows(api, config) {
  const flows = [];
  const seen = new Set();
  for (const sessionKey of uniqueOwnerSessionKeys(config)) {
    const boundFlows = await bindFlowsForSession(api, sessionKey);
    await withTaskBindingClosure(api, [boundFlows], async () => {
      for (const flow of await boundFlows.list()) {
        if (seen.has(flow.flowId) || flow.controllerId !== CONTROLLER_ID) continue;
        seen.add(flow.flowId);
        flows.push(flow);
      }
    });
  }
  return flows;
}

async function resolveFlowBinding(api, config, flowId, preferredSessionKey) {
  const keys = uniqueOwnerSessionKeys(config);
  const ordered = preferredSessionKey
    ? [preferredSessionKey, ...keys.filter((key) => key !== preferredSessionKey)]
    : keys;
  for (const sessionKey of ordered) {
    if (!sessionKey) {
      continue;
    }
    const boundFlows = await bindFlowsForSession(api, sessionKey);
    let flow;
    try {
      flow = await boundFlows.get(flowId);
    } catch (error) {
      await closeTaskBindings(api, [boundFlows], { error });
      throw error;
    }
    if (flow && flow.controllerId === CONTROLLER_ID && stateOf(flow)) {
      return { boundFlows, flow, sessionKey };
    }
    await closeTaskBindings(api, [boundFlows]);
  }
  throw new Error("flow_not_found");
}

async function findMatchingFlow(api, config, repo, prNumber, options = {}) {
  const preferred = ownerSessionKeyForRepo(config, repo);
  const keys = [preferred, ...uniqueOwnerSessionKeys(config).filter((key) => key !== preferred)];
  for (const sessionKey of keys) {
    if (!sessionKey) {
      continue;
    }
    const boundFlows = await bindFlowsForSession(api, sessionKey);
    let flow;
    try {
      flow = latestMatchingFlow(await boundFlows.list(), repo, prNumber, options);
    } catch (error) {
      await closeTaskBindings(api, [boundFlows], { error });
      throw error;
    }
    if (flow) {
      return { boundFlows, flow, sessionKey };
    }
    await closeTaskBindings(api, [boundFlows]);
  }
  return null;
}

function stateOf(flow) {
  return isLifecycleState(flow?.stateJson) ? flow.stateJson : null;
}

function latestMatchingFlow(flows, repo, prNumber, options = {}) {
  const matching = flows
    .filter((flow) => flow.controllerId === CONTROLLER_ID)
    .filter((flow) => flowMatches(stateOf(flow), repo, prNumber))
    .filter((flow) => (options.headSha ? stateOf(flow)?.headSha === options.headSha : true))
    .toSorted((left, right) => (right.updatedAt ?? 0) - (left.updatedAt ?? 0));
  if (options.nonTerminalOnly) {
    return matching.find((flow) => !TERMINAL_FLOW_STATUSES.has(flow.status));
  }
  return matching[0];
}

function flowWaitJson(state) {
  return state.wait ?? { kind: "controller", phase: state.phase };
}

function persistState(boundFlows, flow, state) {
  const common = {
    flowId: flow.flowId,
    expectedRevision: flow.revision,
    currentStep: state.phase,
    stateJson: state,
    updatedAt: state.updatedAt,
  };
  if (state.phase === PHASE.MERGE_READY || state.phase === PHASE.MERGED) {
    return boundFlows.finish({
      flowId: flow.flowId,
      expectedRevision: flow.revision,
      stateJson: state,
      updatedAt: state.updatedAt,
      endedAt: state.updatedAt,
    });
  }
  if (state.phase === PHASE.FAILED) {
    return boundFlows.fail({
      flowId: flow.flowId,
      expectedRevision: flow.revision,
      stateJson: state,
      blockedSummary: state.blocker ?? "PR lifecycle failed",
      updatedAt: state.updatedAt,
      endedAt: state.updatedAt,
    });
  }
  if (
    state.phase === PHASE.BLOCKED ||
    state.phase === PHASE.REVIEW_WAITING ||
    state.phase === PHASE.WAITING_HEAD_EVENT
  ) {
    return boundFlows.setWaiting({
      ...common,
      waitJson: flowWaitJson(state),
      ...(state.phase === PHASE.BLOCKED
        ? { blockedSummary: state.blocker ?? "Manual intervention required" }
        : {}),
    });
  }
  return boundFlows.resume({ ...common, status: "running" });
}

function requireApplied(mutation) {
  if (!mutation.applied) {
    const error = new Error(`flow_mutation_${mutation.code}`);
    error.current = mutation.current;
    throw error;
  }
  return mutation.flow;
}

function recoveryTag(flowId) {
  return `mprl-${flowId.replace(/[^a-zA-Z0-9-]/g, "").slice(0, 24)}`;
}

function notificationTag(flowId) {
  return `mprn-${flowId.replace(/[^a-zA-Z0-9-]/g, "").slice(0, 24)}`;
}

async function clearWake(api, config, flow) {
  const state = stateOf(flow);
  const sessionKeys = new Set([flow?.ownerKey, ownerSessionKeyForRepo(config, state?.repo)]);
  for (const sessionKey of sessionKeys) {
    if (!sessionKey) {
      continue;
    }
    await api.session.workflow.unscheduleSessionTurnsByTag({
      sessionKey,
      tag: recoveryTag(flow.flowId),
    });
  }
}

async function scheduleWake(api, config, flow, kind) {
  const state = stateOf(flow);
  const sessionKey = ownerSessionKeyForRepo(config, state?.repo);
  if (!sessionKey) {
    return undefined;
  }
  const defaultDelayMs = config.recoveryDelayMinutes * 60_000;
  const retryAt = Number.isFinite(state?.infrastructureRetryAt)
    ? state.infrastructureRetryAt
    : null;
  const delayMs =
    kind === "continue"
      ? 1_000
      : Math.max(defaultDelayMs, retryAt === null ? 0 : retryAt - Date.now());
  const action = kind === "continue" ? "continue" : "recover";
  const tag = recoveryTag(flow.flowId);
  await clearWake(api, config, flow);
  return await api.session.workflow.scheduleSessionTurn({
    sessionKey,
    agentId: sessionKey.split(":")[1] || undefined,
    message:
      `Native PR lifecycle wake. Call ${TOOL_NAME} exactly once with ` +
      `${JSON.stringify({ action, flowId: flow.flowId, expectedRevision: flow.revision })}. ` +
      "Do not perform repository work. Do not call message, sessions_send, cron, or any status " +
      "or polling tool. Do not wait for a worker. After the single controller call returns, stop.",
    delayMs,
    deleteAfterRun: true,
    deliveryMode: "none",
    name: `Mergeguez PR lifecycle ${action} ${flow.flowId}`,
    tag,
  });
}

async function notifyMergeReady(api, config, flow, state) {
  if (!config.notificationSessionKey) {
    return undefined;
  }
  const tag = notificationTag(flow.flowId);
  await api.session.workflow.unscheduleSessionTurnsByTag({
    sessionKey: config.notificationSessionKey,
    tag,
  });
  return await api.session.workflow.scheduleSessionTurn({
    sessionKey: config.notificationSessionKey,
    message:
      `PR lifecycle reached merge-ready for ${state.repo}#${state.prNumber} at exact head ` +
      `${state.headSha}. Mergeguez review ${state.mergeReady?.reviewId ?? "(unidentified)"} has ` +
      "complete coverage and zero findings. No merge was attempted. Report this result and wait for explicit merge authorization.",
    delayMs: 1_000,
    deleteAfterRun: true,
    deliveryMode: "announce",
    name: `Merge-ready ${state.repo}#${state.prNumber}`,
    tag,
  });
}

async function notifyMerged(api, config, flow, state) {
  if (!config.notificationSessionKey) {
    return undefined;
  }
  const tag = notificationTag(flow.flowId);
  await api.session.workflow.unscheduleSessionTurnsByTag({
    sessionKey: config.notificationSessionKey,
    tag,
  });
  return await api.session.workflow.scheduleSessionTurn({
    sessionKey: config.notificationSessionKey,
    message:
      `PR lifecycle automatically merged ${state.repo}#${state.prNumber} into exact base dev ` +
      `from exact reviewed head ${state.headSha}. Report the verified merge receipt only.`,
    delayMs: 1_000,
    deleteAfterRun: true,
    deliveryMode: "announce",
    name: `Merged ${state.repo}#${state.prNumber}`,
    tag,
  });
}

async function performAutoMerge(api, config, boundFlows, flow, state) {
  try {
    const receipt = await autoMergeReceipt(api, state);
    const next = mergedState(state, receipt);
    const mergedFlow = requireApplied(await persistState(boundFlows, flow, next));
    await clearWake(api, config, mergedFlow);
    await notifyMerged(api, config, mergedFlow, next);
    return mergedFlow;
  } catch (error) {
    const reason = error instanceof Error ? error.message : "unknown";
    const retryCount = Math.max(0, Number(state.infrastructureRetryCount) || 0);
    if (retryCount < state.maxRetries) {
      const next = {
        ...state,
        infrastructureRetryCount: retryCount + 1,
        infrastructureLastFailure: `auto_merge:${reason}`.slice(0, 500),
        wait: { kind: "auto_merge_retry", since: Date.now() },
        updatedAt: Date.now(),
      };
      const retryFlow = requireApplied(await persistState(boundFlows, flow, next));
      await scheduleWake(api, config, retryFlow, "recover");
      return retryFlow;
    }
    const blocked = blockState(state, `auto_merge_failed:${reason}`);
    const blockedState = { ...blocked.state, mergeReady: state.mergeReady };
    const blockedFlow = requireApplied(await persistState(boundFlows, flow, blockedState));
    await clearWake(api, config, blockedFlow);
    return blockedFlow;
  }
}

function enforceModeGate(state, now = Date.now()) {
  if (state.mode === "observe") {
    return { changed: false, state, effect: "none", reason: "observe_mode" };
  }
  if (state.mode === "dogfood" && state.phase === PHASE.REMEDIATION_QUEUED) {
    return blockState(state, "dogfood_review_complete_live_remediation_not_enabled", now);
  }
  if (state.phase === PHASE.REMEDIATION_QUEUED && state.publisherBoundary?.ready !== true) {
    return blockState(state, "le_commis_publisher_not_attested", now);
  }
  return { changed: false, state, effect: "continue", reason: "mode_allows_step" };
}

async function applyEffect(api, config, boundFlows, flow, state, effect, options = {}) {
  if (effect === "hold") {
    await clearWake(api, config, flow);
    return;
  }
  if (effect === "merge_ready") {
    await clearWake(api, config, flow);
    await notifyMergeReady(api, config, flow, state);
    return;
  }
  if (effect === "continue") {
    const gate = enforceModeGate(state);
    if (gate.changed) {
      const gatedFlow = requireApplied(await persistState(boundFlows, flow, gate.state));
      await scheduleWake(api, config, gatedFlow, "recover");
      return;
    }
    if (gate.reason !== "observe_mode") {
      if (options.dispatchImmediately === true) {
        await clearWake(api, config, flow);
        await dispatchWorker(api, config, boundFlows, flow);
      } else {
        await scheduleWake(api, config, flow, "continue");
      }
    }
    return;
  }
  if (effect === "wait" || effect === "blocked") {
    if (effect === "blocked") {
      await clearWake(api, config, flow);
    } else {
      await scheduleWake(api, config, flow, "recover");
    }
  }
}

function workerAgentId(policy, kind) {
  return kind === "review" ? policy.reviewWorkerAgentId : policy.authorWorkerAgentId;
}

function workerGenerationForState(state) {
  return Math.max(0, Number(state?.workerGeneration) || 0);
}

function createWorkerSessionKey(policy, flow, state, kind) {
  const agent = workerAgentId(policy, kind).replace(/[^a-zA-Z0-9_.-]/g, "-");
  const token = flow.flowId.replace(/[^a-zA-Z0-9]/g, "").slice(0, 16);
  const retryCount = Number.isInteger(state.retryCount) ? state.retryCount : 0;
  const infrastructureRetryCount = Number.isInteger(state.infrastructureRetryCount)
    ? state.infrastructureRetryCount
    : 0;
  const generation = workerGenerationForState(state);
  return `agent:${agent}:subagent:mprl-${token}-${state.cycle}-g${generation}-${retryCount}-i${infrastructureRetryCount}-${kind}`;
}

function contentionWorkspace(policies, repo) {
  if (!policies || typeof policies.get !== "function" || !repo) {
    return null;
  }
  const workspace = policies.get(repo)?.workspace;
  return typeof workspace === "string" && workspace.trim() ? workspace.trim() : null;
}

function sharesReviewContentionDomain(left, right, policies) {
  if (!left?.repo || !right?.repo) {
    return false;
  }
  if (left.repo === right.repo) {
    return true;
  }
  const leftWorkspace = contentionWorkspace(policies, left.repo);
  const rightWorkspace = contentionWorkspace(policies, right.repo);
  return Boolean(leftWorkspace && rightWorkspace && leftWorkspace === rightWorkspace);
}

function activeReviewLeaseHolder(boundFlows, excludedFlowId, candidate, policies) {
  return boundFlows
    .list()
    .filter((flow) => flow.controllerId === CONTROLLER_ID && flow.flowId !== excludedFlowId)
    .filter((flow) => !TERMINAL_FLOW_STATUSES.has(flow.status))
    .find((flow) => {
      const other = stateOf(flow);
      if (other?.activeWorker?.kind !== "review") {
        return false;
      }
      return sharesReviewContentionDomain(other, candidate, policies);
    });
}

function activeAuthorLeaseHolder(boundFlows, excludedFlowId, candidate, policies) {
  return boundFlows
    .list()
    .filter((flow) => flow.controllerId === CONTROLLER_ID && flow.flowId !== excludedFlowId)
    .filter((flow) => !TERMINAL_FLOW_STATUSES.has(flow.status))
    .find((flow) => {
      const other = stateOf(flow);
      if (other?.activeWorker?.kind !== "remediation") {
        return false;
      }
      return sharesReviewContentionDomain(other, candidate, policies);
    });
}

function occupyingWorkerKind(state) {
  const kind = state?.activeWorker?.kind;
  return kind === "review" || kind === "remediation" ? kind : null;
}

function lifecycleFlows(boundFlows) {
  return boundFlows
    .list()
    .filter((flow) => flow.controllerId === CONTROLLER_ID)
    .filter((flow) => !TERMINAL_FLOW_STATUSES.has(flow.status));
}

function domainOccupants(boundFlows, excludedFlowId, candidate, policies) {
  return lifecycleFlows(boundFlows).filter((flow) => {
    if (flow.flowId === excludedFlowId) {
      return false;
    }
    const other = stateOf(flow);
    if (!occupyingWorkerKind(other)) {
      return false;
    }
    return sharesReviewContentionDomain(other, candidate, policies);
  });
}

function globalOccupants(boundFlows, excludedFlowId) {
  return lifecycleFlows(boundFlows).filter((flow) => {
    if (flow.flowId === excludedFlowId) {
      return false;
    }
    return Boolean(occupyingWorkerKind(stateOf(flow)));
  });
}

function readySince(state) {
  if (Number.isFinite(state?.wait?.since)) {
    return state.wait.since;
  }
  return Number(state?.updatedAt) || 0;
}

function olderReadyWaiter(boundFlows, flow, state, policies) {
  return lifecycleFlows(boundFlows)
    .filter((other) => other.flowId !== flow.flowId)
    .filter((other) => {
      const otherState = stateOf(other);
      if (!otherState || occupyingWorkerKind(otherState)) {
        return false;
      }
      if (
        otherState.phase !== PHASE.REVIEW_QUEUED &&
        otherState.phase !== PHASE.REMEDIATION_QUEUED
      ) {
        return false;
      }
      if (otherState.wait?.kind !== "parallel_slot") {
        return false;
      }
      if (!sharesReviewContentionDomain(otherState, state, policies)) {
        return false;
      }
      const otherReady = readySince(otherState);
      const selfReady = readySince(state);
      return otherReady < selfReady || (otherReady === selfReady && other.flowId < flow.flowId);
    })[0];
}

function resolveMaxParallelPrs(config, repo) {
  const policy = config.repositories.get(repo);
  if (Number.isInteger(policy?.maxParallelPrs)) {
    return policy.maxParallelPrs;
  }
  return Number.isInteger(config.maxParallelPrs) ? config.maxParallelPrs : 1;
}

function flowWorkspacePath(policy, state) {
  const recorded =
    (typeof state?.flowWorkspace?.path === "string" && state.flowWorkspace.path.trim()) ||
    (typeof state?.workspacePreflight?.workspace === "string" &&
      state.workspacePreflight.workspace.trim()) ||
    "";
  if (recorded) {
    return recorded;
  }
  return policy.workspace;
}

function provisionedFlowWorkspacePath(policy, state) {
  const cap = Number.isInteger(policy.maxParallelPrs) ? policy.maxParallelPrs : 1;
  if (cap <= 1) {
    return policy.workspace;
  }
  const alias = String(state.repo).split("/").at(-1);
  const parent = policy.workspace.replace(/\/[^/]+$/, "");
  return `${parent}/${alias}-pr${state.prNumber}`;
}

async function addDetachedWorktree(seed, dest, headSha) {
  await execFile("git", ["-C", seed, "worktree", "add", "--detach", dest, headSha], {
    encoding: "utf8",
    maxBuffer: 16_384,
    timeout: 60_000,
    windowsHide: true,
  });
}

async function ensureFlowWorkspace(api, policy, state) {
  if (typeof state?.flowWorkspace?.path === "string" && state.flowWorkspace.path.trim()) {
    return state.flowWorkspace.path.trim();
  }
  if (
    typeof state?.workspacePreflight?.workspace === "string" &&
    state.workspacePreflight.workspace.trim()
  ) {
    return state.workspacePreflight.workspace.trim();
  }
  if (typeof api.testProvisionFlowWorktree === "function") {
    return api.testProvisionFlowWorktree(policy, state);
  }
  const dest = provisionedFlowWorkspacePath(policy, state);
  if (dest === policy.workspace) {
    return dest;
  }
  if (typeof api.testReadWorkspaceHead === "function") {
    return dest;
  }
  await addDetachedWorktree(policy.workspace, dest, state.headSha);
  return dest;
}

function evaluateParallelSlot(config, boundFlows, flow, state, kind) {
  const policies = config.repositories;
  const repoCap = resolveMaxParallelPrs(config, state.repo);
  const occupants = domainOccupants(boundFlows, flow.flowId, state, policies);
  if (occupants.length >= repoCap) {
    return {
      ok: false,
      wait: {
        kind: "parallel_slot",
        since: state.wait?.kind === "parallel_slot" ? state.wait.since : Date.now(),
        position: occupants.length,
        cap: repoCap,
        scope: "repo",
      },
    };
  }
  if (Number.isInteger(config.maxParallelPrsGlobal)) {
    const global = globalOccupants(boundFlows, flow.flowId);
    if (global.length >= config.maxParallelPrsGlobal) {
      return {
        ok: false,
        wait: {
          kind: "parallel_slot",
          since: state.wait?.kind === "parallel_slot" ? state.wait.since : Date.now(),
          position: global.length,
          cap: config.maxParallelPrsGlobal,
          scope: "global",
        },
      };
    }
  }
  if (kind === "review" && activeReviewLeaseHolder(boundFlows, flow.flowId, state, policies)) {
    return {
      ok: false,
      wait: {
        kind: "parallel_slot",
        since: state.wait?.kind === "parallel_slot" ? state.wait.since : Date.now(),
        position: occupants.length + 1,
        cap: repoCap,
        scope: "review_apply",
      },
    };
  }
  const older = olderReadyWaiter(boundFlows, flow, state, policies);
  if (older) {
    return {
      ok: false,
      wait: {
        kind: "parallel_slot",
        since: state.wait?.kind === "parallel_slot" ? state.wait.since : Date.now(),
        position: occupants.length + 1,
        cap: repoCap,
        scope: "fifo",
        aheadFlowId: older.flowId,
      },
    };
  }
  return { ok: true };
}

function workerBinding(flow, state, policy, kind) {
  return {
    flowId: flow.flowId,
    flowRevision: flow.revision,
    repository: state.repo,
    pullRequest: state.prNumber,
    exactHeadSha: state.headSha,
    baseSha: state.baseSha,
    baseRef: state.baseRef,
    cycle: state.cycle,
    mode: state.mode,
    kind,
    reviewActor: state.reviewActor,
    authorActor: state.authorActor,
    publisherBoundary: kind === "remediation" ? state.publisherBoundary : undefined,
    fixerPolicy:
      kind === "remediation"
        ? {
            primaryModel: state.fixerModel,
            fallbackModel: state.fixerFallbackModel,
            forbidAuto: true,
            forbidFast: true,
          }
        : undefined,
    workspace: flowWorkspacePath(policy, state),
    workspacePreflight: state.workspacePreflight ?? null,
    remediationJob: kind === "remediation" ? (state.activeWorker?.remediationJob ?? null) : null,
    findings: kind === "remediation" ? state.findings : [],
  };
}

function buildWorkerMessage(flow, state, policy, kind) {
  const binding = workerBinding(flow, state, policy, kind);
  const common = [
    "You are one bounded worker in a native OpenClaw managed TaskFlow.",
    `Immutable binding: ${JSON.stringify(binding)}`,
    "The controller already verified the isolated workspace head at admission. Do not repeat that local workspace check with exec or another shell call.",
    `Immediately before any external effect, require the broker's authoritative remote PR-head readback to equal ${state.headSha}.`,
    "Use only approved brokered repository routes. Never use raw unauthenticated GitHub writes.",
    "Fail closed on a stale head, incomplete review coverage, lease conflict, ambiguous publication, or missing evidence.",
    "Do not merge. Merge-ready is the terminal automated outcome and still requires separate human authorization.",
  ];
  if (kind === "review") {
    const repositoryAlias = state.repo.split("/").at(-1);
    common.push(
      `Act only as reviewer/gatekeeper ${state.reviewActor}; do not author or modify commits.`,
      "Check the Mergeguez contention-domain fence immediately before launch and preserve at most one active Mergeguez --apply per repository. Different repositories may review in parallel unless they share a workspace.",
      "Use only the executable /home/node/.openclaw/bin/mergeguez. Do not call git, ls, find, head, cat, another executable, or a shell operator, and do not explore or recheck the local workspace.",
      `First call exactly: /home/node/.openclaw/bin/mergeguez pr-state ${repositoryAlias} ${state.prNumber} --json`,
      `Accept existing review evidence only when it is terminal, coverage-complete, and bound to exact head ${state.headSha}.`,
      `If no such terminal review exists, call exactly: /home/node/.openclaw/bin/mergeguez mergeguez-review ${repositoryAlias} ${state.prNumber} --expected-sha ${state.headSha} --apply --json`,
      "For that mergeguez-review exec call, set timeoutSeconds=1800 and yieldMs=1000. If it yields a process session, poll it with timeout=30000 until the process is terminal.",
      `Call ${TOOL_NAME} exactly once with action=report, this flowId, kind=${kind}, headSha=${state.headSha}, and cycle=${state.cycle}.`,
      "After the report tool returns, perform no further repository or review action.",
      "Do not call lifecycle status, admit, continue, recover, or another owner action. The worker reports its result exactly once and never drives the controller.",
      "If completion is external, report outcome=waiting_review with a bounded claimRef.",
      "If authoritative review evidence is already terminal, report approved, changes_requested, failed_retryable, or failed_terminal with coverageComplete and sanitized findings.",
    );
  } else {
    const jobId = state.activeWorker?.remediationJob?.jobId;
    if (!jobId) {
      throw new Error("remediation_job_binding_missing");
    }
    common.push(
      `Act only as author/publisher ${state.authorActor}; never impersonate reviewer ${state.reviewActor}.`,
      `Publish only through attested broker ${state.publisherBoundary.brokerId} under evidence ${state.publisherBoundary.attestationRef}; never substitute another identity or raw GitHub write path.`,
      `Call exactly: ${REMEDIATION_COMMAND} run ${jobId}`,
      "Do not call git, gh, Cursor, a shell, another executable, a shell operator, or any file tool. The bounded command owns scratch isolation, model attestation, validation, commit, publication, and remote-head reconciliation.",
      `The command must attest the exact primary Cursor fixer selector ${state.fixerModel}; Cursor Auto and every Fast selector are forbidden.`,
      "After the command returns, stop. The controller reads and verifies the immutable host evidence directly; do not probe for or call a lifecycle report tool.",
      "If the command fails, stop after accurately stating the returned failure; do not invent evidence or retry the command yourself.",
      `The fallback selector ${state.fixerFallbackModel} is not authorized in this job; a fallback requires a new controller generation after a recorded primary infrastructure failure.`,
    );
  }
  return common.join("\n");
}

async function resolveWorkerTask(api, ownerSessionKey, sessionKey, runId) {
  const worker = { sessionKey, runId, taskId: null };
  const existing = await taskForWorker(api, ownerSessionKey, worker);
  if (existing) {
    return { task: existing, reason: "canonical_worker_task_resolved" };
  }
  return {
    task: undefined,
    reason: "task_link_missing:canonical_worker_task_not_visible",
  };
}

async function dispatchWorker(api, config, boundFlows, flow) {
  let state = stateOf(flow);
  if (!state) {
    throw new Error("flow_state_invalid");
  }
  let workingFlow = flow;
  if (state.phase === PHASE.MERGE_QUEUED) {
    return await performAutoMerge(api, config, boundFlows, workingFlow, state);
  }
  const policy = config.repositories.get(state.repo);
  if (!policy || !policy.enabled) {
    const blocked = blockState(state, "repository_policy_missing_or_disabled");
    return requireApplied(await persistState(boundFlows, flow, blocked.state));
  }
  const gate = enforceModeGate(state);
  if (gate.reason === "observe_mode") {
    return flow;
  }
  if (gate.changed) {
    return requireApplied(await persistState(boundFlows, flow, gate.state));
  }
  const kind = workerKindForPhase(state.phase);
  if (!kind) {
    return workingFlow;
  }
  if (state.orphanedWorker) {
    const orphan = await reconcileOrphanedWorker(api, workingFlow.ownerKey, state.orphanedWorker);
    if (!orphan.safe) {
      await scheduleWake(api, config, workingFlow, "recover");
      return workingFlow;
    }
    state = {
      ...state,
      orphanedWorker: null,
      lastGhostCleanup: {
        sessionKey: state.orphanedWorker.sessionKey,
        runId: state.orphanedWorker.runId ?? null,
        taskId: state.orphanedWorker.taskId ?? null,
        reason: orphan.reason,
        reconciledAt: Date.now(),
      },
      updatedAt: Date.now(),
    };
    workingFlow = requireApplied(await persistState(boundFlows, workingFlow, state));
  }
  const preliminaryCapacity = captureCapacitySnapshot(
    await boundFlows.capacitySnapshot({
      ownerSessionKeys: uniqueOwnerSessionKeys(config),
    }),
  );
  const slot = evaluateParallelSlot(
    config,
    { list: () => preliminaryCapacity.flows },
    workingFlow,
    state,
    kind,
  );
  if (!slot.ok) {
    const queued = {
      ...state,
      wait: slot.wait,
      updatedAt: Date.now(),
    };
    workingFlow = requireApplied(await persistState(boundFlows, workingFlow, queued));
    await scheduleWake(api, config, workingFlow, "recover");
    return workingFlow;
  }
  const workerWorkspace = await ensureFlowWorkspace(api, policy, state);
  let workspaceHead;
  try {
    workspaceHead = await readWorkspaceHead(api, workerWorkspace, state.headSha);
  } catch (error) {
    const detail = error instanceof Error ? error.message : "unknown";
    const blocked = blockState(state, `workspace_head_preflight_failed:${detail.slice(0, 300)}`);
    const blockedFlow = requireApplied(await persistState(boundFlows, workingFlow, blocked.state));
    await applyEffect(api, config, boundFlows, blockedFlow, blocked.state, blocked.effect);
    return blockedFlow;
  }
  if (workspaceHead !== state.headSha) {
    const blocked = blockState(
      state,
      `workspace_head_mismatch:expected=${state.headSha}:actual=${workspaceHead}`,
    );
    const blockedFlow = requireApplied(await persistState(boundFlows, workingFlow, blocked.state));
    await applyEffect(api, config, boundFlows, blockedFlow, blocked.state, blocked.effect);
    return blockedFlow;
  }
  const checkedAt = Date.now();
  state = {
    ...state,
    wait: null,
    flowWorkspace: {
      path: workerWorkspace,
      headSha: workspaceHead,
      provisionedAt: state.flowWorkspace?.provisionedAt ?? checkedAt,
    },
    workspacePreflight: {
      workspace: workerWorkspace,
      headSha: workspaceHead,
      checkedAt,
    },
    updatedAt: checkedAt,
  };
  workingFlow = requireApplied(await persistState(boundFlows, workingFlow, state));
  const sessionKey = createWorkerSessionKey(policy, workingFlow, state, kind);
  const reserved = reserveWorker(state, kind, sessionKey);
  if (reserved.effect === "blocked") {
    const blockedFlow = requireApplied(await persistState(boundFlows, workingFlow, reserved.state));
    await applyEffect(api, config, boundFlows, blockedFlow, reserved.state, reserved.effect);
    return blockedFlow;
  }
  if (!reserved.changed) {
    if (reserved.reason === "infrastructure_backoff") {
      await scheduleWake(api, config, workingFlow, "recover");
    }
    return workingFlow;
  }
  const capacitySnapshot = captureCapacitySnapshot(
    await boundFlows.capacitySnapshot({
      ownerSessionKeys: uniqueOwnerSessionKeys(config),
    }),
  );
  const finalSlot = evaluateParallelSlot(
    config,
    { list: () => capacitySnapshot.flows },
    workingFlow,
    state,
    kind,
  );
  if (!finalSlot.ok) {
    const queued = { ...state, wait: finalSlot.wait, updatedAt: Date.now() };
    workingFlow = requireApplied(await persistState(boundFlows, workingFlow, queued));
    await scheduleWake(api, config, workingFlow, "recover");
    return workingFlow;
  }
  const reservation = await boundFlows.reserve({
    flowId: workingFlow.flowId,
    expectedRevision: workingFlow.revision,
    currentStep: reserved.state.phase,
    stateJson: reserved.state,
    updatedAt: reserved.state.updatedAt,
    status: "running",
    capacitySnapshot,
  });
  if (!reservation.applied && reservation.code === "capacity_snapshot_conflict") {
    const current =
      reservation.current ?? (await boundFlows.get(workingFlow.flowId)) ?? workingFlow;
    await scheduleWake(api, config, current, "recover");
    return current;
  }
  let reservedFlow = requireApplied(reservation);
  let launchedWorker = null;
  let launchInvoked = false;
  try {
    if (kind === "remediation") {
      const remediationJob = prepareRemediationJob(api, reservedFlow, reserved.state, policy);
      const preparedState = {
        ...reserved.state,
        activeWorker: {
          ...reserved.state.activeWorker,
          remediationJob,
        },
        updatedAt: Date.now(),
      };
      reservedFlow = requireApplied(await persistState(boundFlows, reservedFlow, preparedState));
    }
    launchInvoked = true;
    const run = await api.runtime.subagent.run({
      assertCurrent: () => boundFlows.assertCurrent(),
      sessionKey,
      message: buildWorkerMessage(reservedFlow, stateOf(reservedFlow), policy, kind),
      ...(kind === "review" ? { toolsAlsoAllow: [TOOL_NAME] } : {}),
      lane: `mergeguez-pr-lifecycle:${state.repo}:${state.prNumber}`,
      idempotencyKey:
        `mprl:${workingFlow.flowId}:${state.headSha}:${state.cycle}:` +
        `g${workerGenerationForState(state)}:${state.retryCount ?? 0}:` +
        `i${state.infrastructureRetryCount ?? 0}:${kind}`,
      lightContext: true,
      deliver: false,
      cwd: flowWorkspacePath(policy, stateOf(reservedFlow) ?? state),
      runTimeoutSeconds: 3600,
    });
    launchedWorker = {
      ...stateOf(reservedFlow).activeWorker,
      sessionKey:
        typeof run.sessionKey === "string" && run.sessionKey.trim()
          ? run.sessionKey.trim()
          : sessionKey,
      runId: typeof run.runId === "string" && run.runId.trim() ? run.runId.trim() : null,
      taskId: null,
    };
    if (run.sessionKey && run.sessionKey !== sessionKey) {
      throw new Error(`worker_session_identity_mismatch:${run.sessionKey}`);
    }
    let current = (await boundFlows.get(reservedFlow.flowId)) ?? reservedFlow;
    let currentState = stateOf(current);
    if (currentState?.activeWorker?.sessionKey !== sessionKey) {
      throw new Error("worker_reservation_changed_after_launch");
    }
    const attachedRun = attachWorkerRun(currentState, sessionKey, run.runId, null);
    if (attachedRun.changed) {
      reservedFlow = requireApplied(await persistState(boundFlows, current, attachedRun.state));
      current = reservedFlow;
      currentState = attachedRun.state;
    }
    const resolvedTask = await resolveWorkerTask(api, reservedFlow.ownerKey, sessionKey, run.runId);
    if (!resolvedTask.task) {
      throw new Error(resolvedTask.reason);
    }
    const taskId = resolvedTask.task.id ?? resolvedTask.task.taskId ?? null;
    const attachedTask = attachWorkerRun(currentState, sessionKey, run.runId, taskId);
    if (attachedTask.changed) {
      reservedFlow = requireApplied(await persistState(boundFlows, current, attachedTask.state));
    }
    // Worker lifecycle events drive the next transition. A scheduled model turn here
    // would repeatedly wake a controller chat while the worker is legitimately active.
    await clearWake(api, config, reservedFlow);
    return reservedFlow;
  } catch (error) {
    let current;
    try {
      current = (await boundFlows.get(reservedFlow.flowId)) ?? reservedFlow;
    } catch (observationError) {
      // The committed reservation already holds the slot. A failed observation
      // must not turn the original unknown launch into retryable nonexecution.
      if (error && (typeof error === "object" || typeof error === "function")) {
        bindingCleanupEvidence.set(error, Object.freeze([cleanupFailureCode(observationError)]));
      }
      throw error;
    }
    const currentState = stateOf(current);
    if (currentState?.activeWorker?.sessionKey !== sessionKey) {
      throw error;
    }
    const errorMessage = error instanceof Error ? error.message : "unknown";
    if (launchInvoked) {
      const heldState = {
        ...currentState,
        phase: PHASE.BLOCKED,
        blocker: "worker_launch_outcome_unknown",
        wait: { kind: "worker_launch_outcome_unknown", since: Date.now() },
        launchOutcome: {
          status: "unknown",
          sessionKey,
          observedSessionKey: launchedWorker?.sessionKey ?? null,
          runId: launchedWorker?.runId ?? null,
          failure: errorMessage.slice(0, 300),
          observedAt: Date.now(),
        },
        updatedAt: Date.now(),
      };
      const heldFlow = requireApplied(await persistState(boundFlows, current, heldState));
      await clearWake(api, config, heldFlow);
      return heldFlow;
    }
    const failureReason =
      classifyWorkerFailure(errorMessage) === "infrastructure"
        ? errorMessage
        : `worker_start_failed:${errorMessage}`;
    const failed = applyWorkerFailure(currentState, sessionKey, failureReason);
    const failedState =
      failed.changed && launchedWorker?.sessionKey !== sessionKey
        ? {
            ...failed.state,
            orphanedWorker: {
              ...launchedWorker,
              reason: failureReason,
              clearedAt: Date.now(),
            },
          }
        : failed.state;
    const failedFlow = failed.changed
      ? requireApplied(await persistState(boundFlows, current, failedState))
      : current;
    await applyEffect(api, config, boundFlows, failedFlow, failedState, failed.effect);
    return failedFlow;
  }
}

async function ingestPullRequest(api, config, event) {
  const bindings = [];
  return await withTaskBindingClosure(api, bindings, async () => {
    const policy = config.repositories.get(event.repo);
    if (!policy || !policy.enabled) {
      return { accepted: false, reason: "repository_not_enabled" };
    }
    const existingMatch = await findMatchingFlow(api, config, event.repo, event.prNumber, {
      nonTerminalOnly: true,
    });
    if (!existingMatch) {
      const boundFlows = await bindFlowsForSession(api, ownerSessionKeyForRepo(config, event.repo));
      bindings.push(boundFlows);
      const state = createState(event, policy);
      const flow = await boundFlows.createManaged({
        controllerId: CONTROLLER_ID,
        dedupe: { stateFields: ["repo", "prNumber"] },
        goal: `Bring ${event.repo}#${event.prNumber} to exact-head Mergeguez merge-readiness`,
        status: "running",
        notifyPolicy: "silent",
        currentStep: state.phase,
        stateJson: state,
        createdAt: state.startedAt,
        updatedAt: state.updatedAt,
      });
      // A transaction dedupe returns the original row. Never overwrite or wake it
      // using a losing ingress event's freshly constructed state.
      if (!flow.deduplicated && stateOf(flow)?.mode !== "observe") {
        await scheduleWake(api, config, flow, "continue");
      }
      return {
        accepted: true,
        created: flow.deduplicated !== true,
        flowId: flow.flowId,
        revision: flow.revision,
      };
    }
    const { boundFlows, flow: existing } = existingMatch;
    bindings.push(boundFlows);
    const currentState = stateOf(existing);
    const transition = applyPullRequestEvent(currentState, event, policy);
    if (
      currentState?.phase === PHASE.BLOCKED &&
      currentState.blocker === "dogfood_review_complete_live_remediation_not_enabled" &&
      policy.mode === "active"
    ) {
      const base = transition.changed ? transition.state : currentState;
      const refreshed = refreshPolicySnapshot(base, policy, Date.now(), {
        resetDeadline: true,
      }).state;
      const next = {
        ...refreshed,
        phase:
          refreshed.phase === PHASE.REVIEW_QUEUED
            ? PHASE.REVIEW_QUEUED
            : currentState.findings.length > 0
              ? PHASE.REMEDIATION_QUEUED
              : PHASE.REVIEW_QUEUED,
        // A reopened flow is a new execution generation; reusing the old key adopts stale history.
        workerGeneration: workerGenerationForState(currentState) + 1,
        wait: null,
        blocker: null,
        updatedAt: Date.now(),
      };
      const flow = requireApplied(await persistState(boundFlows, existing, next));
      await applyEffect(api, config, boundFlows, flow, next, "continue");
      return {
        accepted: true,
        created: false,
        flowId: flow.flowId,
        revision: flow.revision,
        reason: "active_mode_reopen_dogfood_block",
      };
    }
    if (
      currentState?.phase === PHASE.BLOCKED &&
      currentState.blocker === "le_commis_publisher_not_attested" &&
      policy.mode === "active" &&
      policy.publisherBrokerId &&
      policy.publisherAttestationRef &&
      event.eventId.startsWith("owner-admit:")
    ) {
      const base = transition.changed ? transition.state : currentState;
      const refreshed = refreshPolicySnapshot(base, policy, Date.now(), {
        resetDeadline: true,
      }).state;
      const next = {
        ...refreshed,
        phase: currentState.findings.length > 0 ? PHASE.REMEDIATION_QUEUED : PHASE.REVIEW_QUEUED,
        // A reopened flow is a new execution generation; reusing the old key adopts stale history.
        workerGeneration: workerGenerationForState(currentState) + 1,
        activeWorker: null,
        wait: null,
        blocker: null,
        updatedAt: Date.now(),
      };
      const flow = requireApplied(await persistState(boundFlows, existing, next));
      await applyEffect(api, config, boundFlows, flow, next, "continue");
      return {
        accepted: true,
        created: false,
        flowId: flow.flowId,
        revision: flow.revision,
        reason: "owner_admit_reopen_attested_publisher",
      };
    }
    if (
      currentState?.phase === PHASE.BLOCKED &&
      currentState.blocker === "review_fix_cycle_budget_exhausted" &&
      policy.mode === "active" &&
      policy.maxCycles > currentState.cycle &&
      event.eventId.startsWith("owner-admit:")
    ) {
      const base = transition.changed ? transition.state : currentState;
      const refreshed = refreshPolicySnapshot(base, policy, Date.now(), {
        resetDeadline: true,
      }).state;
      const next = {
        ...refreshed,
        phase: currentState.findings.length > 0 ? PHASE.REMEDIATION_QUEUED : PHASE.REVIEW_QUEUED,
        // A reopened flow is a new execution generation; reusing the old key adopts stale history.
        workerGeneration: workerGenerationForState(currentState) + 1,
        retryCount: 0,
        infrastructureRetryCount: 0,
        infrastructureRetryAt: null,
        infrastructureLastFailure: null,
        orphanedWorker: null,
        activeWorker: null,
        wait: null,
        blocker: null,
        updatedAt: Date.now(),
      };
      const flow = requireApplied(await persistState(boundFlows, existing, next));
      await applyEffect(api, config, boundFlows, flow, next, "continue");
      return {
        accepted: true,
        created: false,
        flowId: flow.flowId,
        revision: flow.revision,
        reason: "owner_admit_reopen_cycle_budget",
      };
    }
    if (
      currentState?.phase === PHASE.BLOCKED &&
      currentState.blocker === "wall_time_budget_exhausted" &&
      policy.mode === "active" &&
      event.eventId.startsWith("owner-admit:")
    ) {
      const base = transition.changed ? transition.state : currentState;
      const refreshed = refreshPolicySnapshot(base, policy, Date.now(), {
        resetDeadline: true,
      }).state;
      const next = {
        ...refreshed,
        phase: currentState.findings.length > 0 ? PHASE.REMEDIATION_QUEUED : PHASE.REVIEW_QUEUED,
        workerGeneration: workerGenerationForState(currentState) + 1,
        activeWorker: null,
        wait: null,
        blocker: null,
        updatedAt: Date.now(),
      };
      const flow = requireApplied(await persistState(boundFlows, existing, next));
      await applyEffect(api, config, boundFlows, flow, next, "continue");
      return {
        accepted: true,
        created: false,
        flowId: flow.flowId,
        revision: flow.revision,
        reason: "owner_admit_reopen_wall_time_budget",
      };
    }
    if (
      currentState?.phase === PHASE.BLOCKED &&
      typeof currentState.blocker === "string" &&
      (currentState.blocker.startsWith("worker_failure_exhausted:") ||
        currentState.blocker === "worker_completed_without_structured_report") &&
      event.eventId.startsWith("owner-admit:")
    ) {
      const base = transition.changed ? transition.state : currentState;
      const refreshed = refreshPolicySnapshot(base, policy, Date.now(), {
        resetDeadline: true,
      }).state;
      const infrastructureRecovery = recoverState(refreshed, undefined, Date.now());
      if (infrastructureRecovery.reason === "legacy_infrastructure_block_requeued") {
        const flow = requireApplied(
          await persistState(boundFlows, existing, infrastructureRecovery.state),
        );
        await applyEffect(
          api,
          config,
          boundFlows,
          flow,
          infrastructureRecovery.state,
          infrastructureRecovery.effect,
        );
        return {
          accepted: true,
          created: false,
          flowId: flow.flowId,
          revision: flow.revision,
          reason: "owner_admit_requeue_infrastructure_failure",
        };
      }
      const next = {
        ...refreshed,
        phase:
          policy.mode === "active" && currentState.findings.length > 0
            ? PHASE.REMEDIATION_QUEUED
            : PHASE.REVIEW_QUEUED,
        retryCount: 0,
        infrastructureRetryCount: 0,
        workerGeneration: workerGenerationForState(currentState) + 1,
        infrastructureRetryAt: null,
        infrastructureLastFailure: null,
        orphanedWorker: null,
        activeWorker: null,
        wait: null,
        blocker: null,
        updatedAt: Date.now(),
      };
      const flow = requireApplied(await persistState(boundFlows, existing, next));
      await applyEffect(api, config, boundFlows, flow, next, "continue");
      return {
        accepted: true,
        created: false,
        flowId: flow.flowId,
        revision: flow.revision,
        reason: "owner_admit_reopen_worker_failure",
      };
    }
    if (
      currentState?.phase === PHASE.BLOCKED &&
      typeof currentState.blocker === "string" &&
      (currentState.blocker === "findings_unusable" ||
        currentState.blocker === "changes_requested_without_actionable_paths") &&
      event.eventId.startsWith("owner-admit:")
    ) {
      const base = transition.changed ? transition.state : currentState;
      const refreshed = refreshPolicySnapshot(base, policy, Date.now(), {
        resetDeadline: true,
      }).state;
      const next = {
        ...refreshed,
        phase: PHASE.REVIEW_QUEUED,
        review: null,
        findings: [],
        retryCount: 0,
        infrastructureRetryCount: 0,
        workerGeneration: workerGenerationForState(currentState) + 1,
        infrastructureRetryAt: null,
        infrastructureLastFailure: null,
        orphanedWorker: null,
        activeWorker: null,
        wait: null,
        blocker: null,
        updatedAt: Date.now(),
      };
      const flow = requireApplied(await persistState(boundFlows, existing, next));
      await applyEffect(api, config, boundFlows, flow, next, "continue");
      return {
        accepted: true,
        created: false,
        flowId: flow.flowId,
        revision: flow.revision,
        reason: "owner_admit_reopen_unusable_findings",
      };
    }
    if (event.eventId.startsWith("owner-admit:")) {
      const base = transition.changed ? transition.state : currentState;
      const refreshed = refreshPolicySnapshot(base, policy, Date.now(), {
        resetDeadline: true,
      }).state;
      const flow = requireApplied(await persistState(boundFlows, existing, refreshed));
      const effect =
        workerKindForPhase(refreshed.phase) && !refreshed.activeWorker ? "continue" : "none";
      await applyEffect(api, config, boundFlows, flow, refreshed, effect);
      return {
        accepted: true,
        created: false,
        flowId: flow.flowId,
        revision: flow.revision,
        reason: "owner_admit_policy_refreshed",
      };
    }
    if (!transition.changed) {
      return {
        accepted: true,
        created: false,
        flowId: existing.flowId,
        revision: existing.revision,
        reason: transition.reason,
      };
    }
    const flow = requireApplied(await persistState(boundFlows, existing, transition.state));
    await applyEffect(api, config, boundFlows, flow, transition.state, transition.effect);
    return { accepted: true, created: false, flowId: flow.flowId, revision: flow.revision };
  });
}

async function ingestReviewResult(api, config, event) {
  const bindings = [];
  return await withTaskBindingClosure(api, bindings, async () => {
    const match = await findMatchingFlow(api, config, event.repo, event.prNumber, {
      headSha: event.headSha,
      nonTerminalOnly: true,
    });
    if (!match) {
      return { accepted: false, reason: "matching_active_flow_not_found" };
    }
    const { boundFlows, flow } = match;
    bindings.push(boundFlows);
    const transition = applyReviewResult(stateOf(flow), event);
    if (!transition.changed) {
      return {
        accepted: true,
        flowId: flow.flowId,
        revision: flow.revision,
        reason: transition.reason,
      };
    }
    let nextState = transition.state;
    let nextEffect = transition.effect;
    const gate = enforceModeGate(nextState);
    if (gate.changed) {
      nextState = gate.state;
      nextEffect = gate.effect;
    }
    const updated = requireApplied(await persistState(boundFlows, flow, nextState));
    await applyEffect(api, config, boundFlows, updated, nextState, nextEffect, {
      dispatchImmediately: true,
    });
    const current = (await boundFlows.get(updated.flowId)) ?? updated;
    return { accepted: true, flowId: current.flowId, revision: current.revision };
  });
}

function createRouteHandler(options) {
  const rateLimiter = createFixedWindowLimiter();
  const inFlightLimiter = createInFlightLimiter();
  return async (req, res) => {
    const key = requestKey(req, options.kind);
    let release;
    try {
      requireJsonPost(req);
      if (!rateLimiter.allow(key)) {
        throw new Error("rate_limited");
      }
      release = inFlightLimiter.acquire(key);
      if (!release) {
        throw new Error("too_many_in_flight");
      }
      const { body, json } = await readJsonBody(req);
      const signatureHeader =
        options.kind === "github"
          ? req.headers["x-hub-signature-256"]
          : req.headers["x-mergeguez-signature-256"];
      const signature = Array.isArray(signatureHeader) ? signatureHeader[0] : signatureHeader;
      if (!verifySha256Signature(body, options.secret, signature)) {
        throw new Error("invalid_signature");
      }
      const event =
        options.kind === "github"
          ? parseGitHubPullRequest(req, json)
          : parseMergeguezReviewEvent(req, json);
      const outcome = await options.ingest(event);
      writeJson(res, 202, { ok: true, ...outcome });
      return true;
    } catch (error) {
      const mapped = mapHttpError(error);
      writeJson(res, mapped.status, { ok: false, error: mapped.code });
      return true;
    } finally {
      release?.();
    }
  };
}

function statusView(flow) {
  const state = stateOf(flow);
  if (!state) {
    return null;
  }
  return {
    flowId: flow.flowId,
    revision: flow.revision,
    status: flow.status,
    repo: state.repo,
    prNumber: state.prNumber,
    headSha: state.headSha,
    phase: state.phase,
    cycle: state.cycle,
    retryCount: state.retryCount,
    infrastructureRetryCount: state.infrastructureRetryCount ?? 0,
    workerGeneration: workerGenerationForState(state),
    infrastructureRetryAt: state.infrastructureRetryAt ?? null,
    infrastructureLastFailure: state.infrastructureLastFailure ?? null,
    deadlineAt: state.deadlineAt,
    fixerModel: state.fixerModel ?? null,
    fixerFallbackModel: state.fixerFallbackModel ?? null,
    publisherBoundary: state.publisherBoundary ?? null,
    fixerAttestation: state.fixerAttestation ?? null,
    workspacePreflight: state.workspacePreflight ?? null,
    flowWorkspace: state.flowWorkspace ?? null,
    queuedPosition: state.wait?.kind === "parallel_slot" ? state.wait.position : null,
    lastGhostCleanup: state.lastGhostCleanup ?? null,
    activeWorker: state.activeWorker
      ? {
          kind: state.activeWorker.kind,
          sessionKey: state.activeWorker.sessionKey,
          runId: state.activeWorker.runId,
          taskId: state.activeWorker.taskId,
        }
      : null,
    review: state.review,
    findingsCount: state.findings.length,
    wait: state.wait,
    blocker: state.blocker,
    mergeReady: state.mergeReady,
    merged: state.merged ?? null,
  };
}

function agentIdFromSessionKey(sessionKey) {
  if (typeof sessionKey !== "string") {
    return null;
  }
  const match = /^agent:([^:]+):/.exec(sessionKey);
  return match?.[1] ?? null;
}

function requireOwnerContext(ctx, ownerSessionKey) {
  if (!ownerSessionKey || ctx.sessionKey !== ownerSessionKey) {
    throw new Error("controller_action_requires_owner_session");
  }
}

function canInspectStatus(config, ctx, ownerSessionKey, state) {
  if (ctx.sessionKey === ownerSessionKey || state?.activeWorker?.sessionKey === ctx.sessionKey) {
    return true;
  }
  const agentId =
    typeof ctx.agentId === "string" && ctx.agentId.trim()
      ? ctx.agentId.trim()
      : agentIdFromSessionKey(ctx.sessionKey);
  return Boolean(agentId && config.statusAgentIds.includes(agentId));
}

function workerTaskMatches(worker, task) {
  if (!worker || !task) {
    return false;
  }
  const agentId = agentIdFromSessionKey(worker.sessionKey);
  const taskSessionKey = task.childSessionKey ?? task.sessionKey;
  if (taskSessionKey !== worker.sessionKey) {
    return false;
  }
  if (task.agentId && agentId && task.agentId !== agentId) {
    return false;
  }
  if (worker.runId) {
    return task.runId === worker.runId;
  }
  return task.childSessionKey === worker.sessionKey;
}

function workerAgentMainSessionKey(workerSessionKey) {
  const agentId = agentIdFromSessionKey(workerSessionKey);
  return agentId ? `agent:${agentId}:main` : null;
}

async function workerTaskLedgers(api, ownerSessionKey, worker) {
  const agentId = agentIdFromSessionKey(worker.sessionKey) ?? undefined;
  const ownerAgentId = agentIdFromSessionKey(ownerSessionKey) ?? undefined;
  const workerMainSessionKey = workerAgentMainSessionKey(worker.sessionKey);
  const bindings = [
    {
      sessionKey: worker.sessionKey,
      agentId,
    },
    ...(workerMainSessionKey ? [{ sessionKey: workerMainSessionKey, agentId }] : []),
    ...(ownerSessionKey ? [{ sessionKey: ownerSessionKey, agentId: ownerAgentId }] : []),
  ];
  const seen = new Set();
  const ledgers = [];
  for (const binding of bindings) {
    const key = `${binding.sessionKey}\u0000${binding.agentId ?? ""}`;
    if (!binding.sessionKey || seen.has(key)) {
      continue;
    }
    seen.add(key);
    let ledger;
    try {
      ledger = await api.runtime.tasks.runs.bindSession(binding);
    } catch {
      // One inaccessible ledger must not hide an exact task from another owner/worker ledger.
      continue;
    }
    if (["get", "list", "cancel", "close"].some((name) => typeof ledger?.[name] !== "function")) {
      const error = new Error("publisher_run_parity_port_unavailable");
      const owned = typeof ledger?.close === "function" ? [...ledgers, ledger] : ledgers;
      await closeTaskBindings(api, owned, { error });
      throw error;
    }
    ledgers.push(ledger);
  }
  return ledgers;
}

async function taskForWorker(api, ownerSessionKey, worker) {
  if (!worker?.sessionKey) {
    return undefined;
  }
  const ledgers = await workerTaskLedgers(api, ownerSessionKey, worker);
  return await withTaskBindingClosure(api, ledgers, async () => {
    if (worker.taskId) {
      for (const runs of ledgers) {
        const exact = await runs.get(worker.taskId);
        if (workerTaskMatches(worker, exact)) {
          return exact;
        }
      }
    }
    const seenTaskIds = new Set();
    for (const runs of ledgers) {
      for (const task of await runs.list()) {
        if (!task?.id || seenTaskIds.has(task.id)) {
          continue;
        }
        seenTaskIds.add(task.id);
        if (workerTaskMatches(worker, task)) {
          return task;
        }
      }
    }
    return undefined;
  });
}

async function currentWorkerTask(api, ownerSessionKey, state) {
  return await taskForWorker(api, ownerSessionKey, state.activeWorker);
}

function workerMatchesTerminalLifecycleEvent(worker, event) {
  if (
    !worker ||
    event?.stream !== "lifecycle" ||
    !new Set(["end", "error"]).has(event?.data?.phase)
  ) {
    return false;
  }
  if (worker.runId) {
    return event.runId === worker.runId;
  }
  return Boolean(event.sessionKey && event.sessionKey === worker.sessionKey);
}

async function reconcileTerminalWorkerEvent(api, config, event) {
  const bindings = [];
  return await withTaskBindingClosure(api, bindings, async () => {
    if (event?.stream !== "lifecycle" || !new Set(["end", "error"]).has(event?.data?.phase)) {
      return { handled: false, reason: "not_terminal_worker_event" };
    }
    for (const candidate of await collectLifecycleFlows(api, config)) {
      const candidateState = stateOf(candidate);
      if (!workerMatchesTerminalLifecycleEvent(candidateState?.activeWorker, event)) {
        continue;
      }
      const resolved = await resolveFlowBinding(api, config, candidate.flowId, candidate.ownerKey);
      const boundFlows = resolved.boundFlows;
      bindings.push(boundFlows);
      let flow = resolved.flow;
      let state = stateOf(flow);
      if (!workerMatchesTerminalLifecycleEvent(state?.activeWorker, event)) {
        return { handled: false, reason: "worker_event_superseded" };
      }

      if (state.activeWorker.kind === "remediation") {
        const evidence = await reconcileRemediationEvidence(api, config, boundFlows, flow);
        if (evidence.changed) {
          flow = (await boundFlows.get(flow.flowId)) ?? evidence.flow;
          return {
            handled: true,
            reason: evidence.reason,
            flow: statusView(flow),
          };
        }
        if (event.data.phase === "end") {
          // The host command writes immutable evidence before returning. If filesystem
          // visibility trails the terminal event, use one bounded controller wake.
          await scheduleWake(api, config, flow, "recover");
          return {
            handled: true,
            reason: "remediation_evidence_pending",
            flow: statusView(flow),
          };
        }
      }

      const observedTask = await currentWorkerTask(api, resolved.sessionKey, state);
      // Lifecycle notifications only wake reconciliation. Exact original-owner
      // observation (or immutable remediation evidence above) supplies outcome.
      if (!observedTask || !TERMINAL_TASK_STATUSES.has(observedTask.status)) {
        await scheduleWake(api, config, flow, "recover");
        const unknown =
          observedTask?.status === "unknown"
            ? recoverObservedState(state, observedTask).reason
            : "worker_terminal_observation_pending";
        return { handled: true, reason: unknown, flow: statusView(flow) };
      }
      const terminalTask = observedTask;
      const transition = recoverObservedState(state, terminalTask, Date.now(), 0, {
        processStartedAt: processStartedAtMs(),
        sessionAlive: false,
      });
      if (transition.changed) {
        flow = requireApplied(await persistState(boundFlows, flow, transition.state));
        state = transition.state;
      }
      await applyEffect(api, config, boundFlows, flow, state, transition.effect, {
        dispatchImmediately: true,
      });
      flow = (await boundFlows.get(flow.flowId)) ?? flow;
      return { handled: true, reason: transition.reason, flow: statusView(flow) };
    }
    return { handled: false, reason: "active_worker_not_found" };
  });
}

const ACTIVE_TASK_STATUSES = new Set(["queued", "running"]);
const TERMINAL_TASK_STATUSES = new Set(["succeeded", "failed", "timed_out", "cancelled", "lost"]);

async function reconcileOrphanedWorker(api, ownerSessionKey, orphanedWorker) {
  if (!orphanedWorker?.sessionKey) {
    return { safe: true, reason: "no_orphan" };
  }
  const task = await taskForWorker(api, ownerSessionKey, orphanedWorker);
  if (
    ["native-subagent", "legacy-task"].includes(task?.observationSource) &&
    task.status === "unknown"
  ) {
    return {
      safe: false,
      reason:
        task.observationSource === "native-subagent"
          ? "orphan_native_outcome_unknown"
          : "orphan_legacy_outcome_unknown",
      task,
    };
  }
  if (task && TERMINAL_TASK_STATUSES.has(task.status)) {
    return { safe: true, reason: "orphan_task_terminal", task };
  }
  const alive = sessionAlive(api, orphanedWorker.sessionKey);
  if (task?.observationSource === "legacy-task" && ACTIVE_TASK_STATUSES.has(task.status)) {
    return { safe: false, reason: "orphan_legacy_cancellation_unavailable", task };
  }
  if (task && ACTIVE_TASK_STATUSES.has(task.status)) {
    const ledgers = await workerTaskLedgers(api, ownerSessionKey, orphanedWorker);
    const cancelledTask = await withTaskBindingClosure(api, ledgers, async () => {
      for (const runs of ledgers) {
        const exact = await runs.get(task.id);
        if (!workerTaskMatches(orphanedWorker, exact) || typeof runs.cancel !== "function") {
          continue;
        }
        try {
          const cancelled = await runs.cancel({ taskId: task.id, cfg: api.config });
          if (
            !cancelled?.error &&
            (cancelled?.cancelled === true || TERMINAL_TASK_STATUSES.has(cancelled?.task?.status))
          ) {
            return { safe: true, reason: "orphan_task_cancelled", task: cancelled.task ?? task };
          }
          if (task.observationSource === "native-subagent") {
            return { safe: false, reason: "orphan_native_cancellation_unknown", task };
          }
        } catch {
          if (task.observationSource === "native-subagent") {
            return { safe: false, reason: "orphan_native_cancellation_unknown", task };
          }
          // Preserve the predecessor fallback only for its untagged historical projection.
        }
      }
    });
    if (cancelledTask) return cancelledTask;
  }
  if (alive === false) {
    return { safe: true, reason: task ? "orphan_session_dead_task_stale" : "orphan_session_dead" };
  }
  return {
    safe: false,
    reason: alive === true ? "orphan_session_still_alive" : "orphan_session_liveness_unknown",
  };
}

const DEAD_SESSION_STATUSES = new Set([
  "failed",
  "done",
  "cancelled",
  "aborted",
  "timeout",
  "timed_out",
]);

function sessionAlive(api, sessionKey) {
  if (typeof sessionKey !== "string" || !sessionKey) {
    return undefined;
  }
  const getSessionEntry = api.runtime?.agent?.session?.getSessionEntry;
  if (typeof getSessionEntry !== "function") {
    return undefined;
  }
  const agentId = agentIdFromSessionKey(sessionKey) ?? undefined;
  let entry;
  try {
    entry = getSessionEntry({ agentId, sessionKey });
  } catch {
    return undefined;
  }
  if (!entry || entry.endedAt || entry.abortedLastRun === true) {
    return false;
  }
  const status = typeof entry.status === "string" ? entry.status.toLowerCase() : "";
  if (DEAD_SESSION_STATUSES.has(status)) {
    return false;
  }
  return true;
}

function workerSessionAlive(api, state) {
  return sessionAlive(api, state?.activeWorker?.sessionKey);
}

function recoverExtras(api, state) {
  return {
    processStartedAt: processStartedAtMs(),
    sessionAlive: workerSessionAlive(api, state),
  };
}

function toolSchema() {
  return {
    type: "object",
    additionalProperties: false,
    properties: {
      action: { type: "string", enum: ["status", "continue", "recover", "report", "admit"] },
      flowId: { type: "string", minLength: 1 },
      repo: { type: "string", minLength: 1 },
      prNumber: { type: "integer", minimum: 1 },
      baseSha: { type: "string", pattern: "^[0-9a-f]{40}$" },
      baseRef: { type: "string", minLength: 1 },
      expectedRevision: { type: "integer", minimum: 0 },
      kind: { type: "string", enum: ["review", "remediation"] },
      outcome: { type: "string", minLength: 1 },
      headSha: { type: "string", pattern: "^[0-9a-f]{40}$" },
      cycle: { type: "integer", minimum: 0 },
      reviewId: { type: "string" },
      summary: { type: "string" },
      claimRef: { type: "string" },
      newHeadSha: { type: "string", pattern: "^[0-9a-f]{40}$" },
      coverageComplete: { type: "boolean" },
      retryAllowed: { type: "boolean" },
      testsPassed: { type: "boolean" },
      publicationConfirmed: { type: "boolean" },
      verificationComplete: { type: "boolean" },
      fixerModel: { type: "string", minLength: 1 },
      fixerAttested: { type: "boolean" },
      fixerAttestationRef: { type: "string", minLength: 1 },
      fixerFallbackReason: { type: "string", minLength: 1 },
      fixerPrimaryFailureRef: { type: "string", minLength: 1 },
      findings: {
        type: "array",
        maxItems: 50,
        items: {
          type: "object",
          additionalProperties: false,
          required: ["id", "severity", "summary"],
          properties: {
            id: { type: "string" },
            severity: { type: "string", enum: ["blocker", "high", "medium", "low", "info"] },
            summary: { type: "string" },
            path: { type: "string" },
            line: { type: "integer", minimum: 1 },
            evidence: { type: "string" },
          },
        },
      },
    },
    required: ["action"],
  };
}

function createControllerTool(api, config, ctx) {
  return {
    name: TOOL_NAME,
    label: "Mergeguez PR lifecycle",
    description:
      "Inspect, continue, recover, or report one exact-head Mergeguez PR lifecycle TaskFlow.",
    parameters: toolSchema(),
    execute: async (_toolCallId, input) => {
      const bindings = [];
      return await withTaskBindingClosure(api, bindings, async () => {
        if (!config.enabled || !config.ownerSessionKey) {
          throw new Error("mergeguez_pr_lifecycle_is_not_enabled");
        }
        if (input.action === "admit") {
          const event = normalizePullRequestEvent({
            eventId: `owner-admit:${Date.now()}:${input.headSha ?? "missing"}`,
            action: "synchronize",
            repo: input.repo,
            prNumber: input.prNumber,
            headSha: input.headSha,
            baseSha: input.baseSha,
            baseRef: input.baseRef,
            headRepo: input.repo,
          });
          requireOwnerContext(ctx, ownerSessionKeyForRepo(config, event.repo));
          const ingested = await ingestPullRequest(api, config, event);
          const match = await findMatchingFlow(api, config, event.repo, event.prNumber);
          if (match) bindings.push(match.boundFlows);
          return result({
            ok: true,
            admit: ingested,
            flow: match?.flow ? statusView(match.flow) : null,
          });
        }
        if (!input.flowId) {
          throw new Error("flowId is required");
        }
        const resolved = await resolveFlowBinding(api, config, input.flowId, ctx.sessionKey);
        const boundFlows = resolved.boundFlows;
        bindings.push(boundFlows);
        let flow = resolved.flow;
        let state = stateOf(flow);
        const ownerKey = ownerSessionKeyForRepo(config, state.repo);
        if (input.action === "status") {
          if (!canInspectStatus(config, ctx, ownerKey, state)) {
            throw new Error("flow_status_not_visible_to_this_session");
          }
          return result(statusView(flow));
        }
        if (input.action === "report") {
          if (
            input.kind === "remediation" &&
            (input.outcome === "fixed_and_published" || input.outcome === "re_review_same_head")
          ) {
            verifyRemediationEvidence(api, state, input);
          }
          const transition = applyWorkerReport(state, input, ctx.sessionKey);
          flow = requireApplied(await persistState(boundFlows, flow, transition.state));
          let nextState = transition.state;
          let nextEffect = transition.effect;
          const gate = enforceModeGate(nextState);
          if (gate.changed) {
            nextState = gate.state;
            nextEffect = gate.effect;
            flow = requireApplied(await persistState(boundFlows, flow, nextState));
          }
          await applyEffect(api, config, boundFlows, flow, nextState, nextEffect, {
            dispatchImmediately: true,
          });
          flow = (await boundFlows.get(flow.flowId)) ?? flow;
          return result({ ok: true, transition: transition.reason, flow: statusView(flow) });
        }
        requireOwnerContext(ctx, ownerKey);
        if (input.expectedRevision !== undefined && input.expectedRevision !== flow.revision) {
          return result({
            ok: true,
            staleWake: true,
            expectedRevision: input.expectedRevision,
            flow: statusView(flow),
          });
        }
        if (input.action === "recover") {
          requireOwnerContext(ctx, ownerKey);
          const policy = config.repositories.get(state.repo);
          if (!policy || !policy.enabled) {
            throw new Error("repository_policy_missing_or_disabled");
          }
          const refreshed = refreshPolicySnapshot(state, policy);
          if (refreshed.changed) {
            flow = requireApplied(await persistState(boundFlows, flow, refreshed.state));
          }
          state = stateOf(flow);
          const evidence = await reconcileRemediationEvidence(api, config, boundFlows, flow);
          if (evidence.changed) {
            return result({ ok: true, recovery: evidence.reason, flow: statusView(evidence.flow) });
          }
          const transition = recoverObservedState(
            state,
            await currentWorkerTask(api, resolved.sessionKey, state),
            Date.now(),
            120_000,
            recoverExtras(api, state),
          );
          if (transition.changed) {
            flow = requireApplied(await persistState(boundFlows, flow, transition.state));
          }
          if (transition.effect === "hold") {
            await clearWake(api, config, flow);
          } else if (transition.effect === "continue") {
            flow = await dispatchWorker(api, config, boundFlows, flow);
          } else if (
            !isTerminalState(transition.state) &&
            transition.state.phase !== PHASE.BLOCKED
          ) {
            await scheduleWake(api, config, flow, "recover");
          }
          return result({ ok: true, recovery: transition.reason, flow: statusView(flow) });
        }
        if (input.action === "continue") {
          flow = await dispatchWorker(api, config, boundFlows, flow);
          return result({ ok: true, flow: statusView(flow) });
        }
        throw new Error("unsupported_action");
      });
    },
  };
}

function processStartedAtMs() {
  return Date.now() - Math.floor(process.uptime() * 1000);
}

async function reconcileAtStartup(api, config) {
  const bindings = [];
  return await withTaskBindingClosure(api, bindings, async () => {
    if (!config.enabled || !config.ownerSessionKey) {
      return;
    }
    for (const sessionKey of uniqueOwnerSessionKeys(config)) {
      const boundFlows = await bindFlowsForSession(api, sessionKey);
      bindings.push(boundFlows);
      for (let flow of (await boundFlows.list()).filter(
        (item) => item.controllerId === CONTROLLER_ID,
      )) {
        let state = stateOf(flow);
        if (!state) {
          continue;
        }
        if (flow.status === "blocked" || state.phase === PHASE.BLOCKED) {
          await clearWake(api, config, flow);
          continue;
        }
        if (TERMINAL_FLOW_STATUSES.has(flow.status) || isTerminalState(state)) {
          await clearWake(api, config, flow);
          continue;
        }
        const policy = config.repositories.get(state.repo);
        if (!policy || !policy.enabled) {
          await clearWake(api, config, flow);
          continue;
        }
        const refreshed = refreshPolicySnapshot(state, policy);
        if (refreshed.changed) {
          flow = requireApplied(await persistState(boundFlows, flow, refreshed.state));
          state = refreshed.state;
        }
        const evidence = await reconcileRemediationEvidence(api, config, boundFlows, flow);
        if (evidence.changed) {
          continue;
        }
        if (state.mode === "observe") {
          await clearWake(api, config, flow);
          continue;
        }
        const transition = recoverObservedState(
          state,
          await currentWorkerTask(api, sessionKey, state),
          Date.now(),
          120_000,
          recoverExtras(api, state),
        );
        if (transition.changed) {
          flow = requireApplied(await persistState(boundFlows, flow, transition.state));
          state = transition.state;
        }
        if (transition.effect === "hold") {
          await clearWake(api, config, flow);
        } else if (transition.effect === "continue") {
          await scheduleWake(api, config, flow, "continue");
        } else if (!isTerminalState(state) && state.phase !== PHASE.BLOCKED) {
          await scheduleWake(api, config, flow, "recover");
        } else {
          await clearWake(api, config, flow);
        }
      }
    }
  });
}

export function registerMergeguezPrLifecycle(api) {
  const requestedConfig = normalizeRuntimeConfig(api.pluginConfig ?? {});
  const sourceIntegrity = runtimeSourceIntegrity(
    requestedConfig.expectedRuntimePath,
    requestedConfig.expectedRuntimeSha256,
    { allowDisposable: api.testAllowDisposableRuntime === true },
  );
  const parityOwnerReady =
    api.runtime?.tasks?.authorityVersion === 1 &&
    api.runtime.tasks.availability?.controllerParity === true &&
    typeof api.runtime.tasks.managedFlows?.bindSession === "function" &&
    typeof api.runtime.tasks.runs?.bindSession === "function";
  const config =
    requestedConfig.enabled && (!sourceIntegrity.verified || !parityOwnerReady)
      ? { ...requestedConfig, enabled: false }
      : requestedConfig;
  api.registerTool((ctx) => createControllerTool(api, config, ctx), {
    names: [TOOL_NAME],
    optional: true,
  });

  if (requestedConfig.enabled && !sourceIntegrity.verified) {
    api.logger.error(
      `Mergeguez PR lifecycle runtime source integrity failed; controller remains inert. ` +
        `Loaded ${sourceIntegrity.path} at sha256:${sourceIntegrity.sha256}; ` +
        `durable=${sourceIntegrity.durable}.`,
    );
    return;
  }
  if (requestedConfig.enabled && !parityOwnerReady) {
    api.logger.error(
      "Publisher current-behavior compatibility owner is unavailable; controller remains inert.",
    );
    return;
  }
  if (!config.enabled) {
    api.logger.info("Mergeguez PR lifecycle controller is installed but disabled.");
    return;
  }
  if (!config.ownerSessionKey) {
    api.logger.error(
      "Mergeguez PR lifecycle enabled without ownerSessionKey; runtime remains inert.",
    );
    return;
  }
  api.logger.info(
    `Mergeguez PR lifecycle runtime source verified: ${sourceIntegrity.path} ` +
      `sha256:${sourceIntegrity.sha256}.`,
  );

  if (config.githubWebhookSecret) {
    api.registerHttpRoute({
      path: config.githubWebhookPath,
      auth: "plugin",
      match: "exact",
      handler: createRouteHandler({
        kind: "github",
        secret: config.githubWebhookSecret,
        ingest: (event) => ingestPullRequest(api, config, event),
      }),
    });
  } else {
    api.logger.warn("GitHub webhook route not registered because its secret is unavailable.");
  }

  if (config.mergeguezEventSecret) {
    api.registerHttpRoute({
      path: config.mergeguezEventPath,
      auth: "plugin",
      match: "exact",
      handler: createRouteHandler({
        kind: "mergeguez",
        secret: config.mergeguezEventSecret,
        ingest: (event) => ingestReviewResult(api, config, event),
      }),
    });
  } else {
    api.logger.warn("Mergeguez event route not registered because its secret is unavailable.");
  }

  api.agent.events.registerAgentEventSubscription({
    id: "worker-terminal-reconciliation",
    description:
      "Advance exact-head PR lifecycle flows from terminal worker events without chat polling.",
    streams: ["lifecycle"],
    async handle(event) {
      try {
        await reconcileTerminalWorkerEvent(api, config, event);
      } catch (error) {
        const detail = error instanceof Error ? error.message : "unknown";
        api.logger.error(`Mergeguez PR lifecycle terminal reconciliation failed: ${detail}`);
      }
    },
  });

  api.registerService({
    id: "mergeguez-pr-lifecycle-recovery",
    async start() {
      await reconcileAtStartup(api, config);
    },
  });
}

// eslint-disable-next-line no-underscore-dangle -- This internal test surface is not plugin API.
export const __testing = {
  captureCapacitySnapshot,
  recoverObservedState,
  withTaskBindingClosure,
  bindingCleanupFailureCodes: (error) => bindingCleanupEvidence.get(error) ?? Object.freeze([]),
  normalizeRuntimeConfig,
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
  dispatchWorker,
  reconcileAtStartup,
  processStartedAtMs,
  currentWorkerTask,
  reconcileOrphanedWorker,
  workerMatchesTerminalLifecycleEvent,
  reconcileTerminalWorkerEvent,
  workerSessionAlive,
  recoverExtras,
  activeReviewLeaseHolder,
  activeAuthorLeaseHolder,
  sharesReviewContentionDomain,
  evaluateParallelSlot,
  flowWorkspacePath,
  ensureFlowWorkspace,
  resolveMaxParallelPrs,
  workerAgentId,
  ownerSessionKeyForRepo,
  uniqueOwnerSessionKeys,
  resolveFlowBinding,
  isDisposableRuntimePath,
  readWorkspaceHead,
  runMergeguez,
  autoMergeReceipt,
  mergedState,
  runtimeSourceIntegrity,
};
