import { createHash } from "node:crypto";
import { existsSync, lstatSync } from "node:fs";
import { PHASE } from "./controller.mjs";
import { execFile } from "./runtime-foundation.mjs";
import { readWorkspaceIdentity } from "./runtime-remediation-primitives.mjs";

export function provisionedFlowWorkspacePath(policy, state) {
  const cap = Number.isInteger(policy.maxParallelPrs) ? policy.maxParallelPrs : 1;
  if (cap <= 1) {
    return policy.workspace;
  }
  const alias = String(state.repo)
    .replace(/[^A-Za-z0-9_.-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80);
  const root = (
    policy.remediatorProfile?.worktreeRoot || policy.workspace.replace(/\/[^/]+$/, "")
  ).replace(/\/+$/, "");
  const repoToken = createHash("sha256").update(String(state.repo)).digest("hex").slice(0, 8);
  return `${root}/${alias}-${repoToken}-pr${state.prNumber}`;
}

export async function addDetachedWorktree(seed, dest, headSha) {
  await execFile("git", ["-C", seed, "worktree", "add", "--detach", dest, headSha], {
    encoding: "utf8",
    maxBuffer: 16_384,
    timeout: 60_000,
    windowsHide: true,
  });
}

export async function refreshDetachedWorktree(seed, dest, headSha) {
  const listing = await execFile("git", ["-C", seed, "worktree", "list", "--porcelain"], {
    encoding: "utf8",
    maxBuffer: 256 * 1024,
    timeout: 10_000,
    windowsHide: true,
  });
  const registeredDetached = listing.stdout
    .split(/\n\n+/)
    .map((block) => block.split("\n").filter(Boolean))
    .some((lines) => lines[0] === `worktree ${dest}` && lines.includes("detached"));
  if (!registeredDetached) {
    throw new Error("flow_workspace_not_registered_detached_worktree");
  }
  await execFile("git", ["-C", seed, "cat-file", "-e", `${headSha}^{commit}`], {
    encoding: "utf8",
    maxBuffer: 16_384,
    timeout: 10_000,
    windowsHide: true,
  });
  await execFile("git", ["-C", dest, "checkout", "--detach", headSha], {
    encoding: "utf8",
    maxBuffer: 16_384,
    timeout: 60_000,
    windowsHide: true,
  });
}

export async function ensureFlowWorkspace(api, policy, state) {
  if (typeof api.testProvisionFlowWorktree === "function") {
    return api.testProvisionFlowWorktree(policy, state);
  }
  const dest = provisionedFlowWorkspacePath(policy, state);
  if (dest === policy.workspace) {
    return dest;
  }
  if (
    typeof api.testReadWorkspaceHead === "function" ||
    typeof api["__testReadWorkspaceHead"] === "function"
  ) {
    return dest;
  }
  if (existsSync(dest)) {
    const stat = lstatSync(dest);
    if (!stat.isDirectory() || stat.isSymbolicLink()) {
      throw new Error("flow_workspace_existing_path_invalid");
    }
    const identity = await readWorkspaceIdentity(api, dest, state.headSha, state.repo);
    if (identity.topLevel !== dest || identity.repository !== state.repo) {
      throw new Error("flow_workspace_existing_identity_invalid");
    }
    if (identity.clean !== true) {
      throw new Error("flow_workspace_existing_dirty");
    }
    if (identity.headSha !== state.headSha) {
      await refreshDetachedWorktree(policy.workspace, dest, state.headSha);
      const refreshed = await readWorkspaceIdentity(api, dest, state.headSha, state.repo);
      if (
        refreshed.topLevel !== dest ||
        refreshed.repository !== state.repo ||
        refreshed.clean !== true ||
        refreshed.headSha !== state.headSha
      ) {
        throw new Error("flow_workspace_refresh_verification_failed");
      }
    }
    return dest;
  }
  await addDetachedWorktree(policy.workspace, dest, state.headSha);
  return dest;
}

export function isWorkspaceHeadMismatchBlock(state) {
  return (
    state?.phase === PHASE.BLOCKED &&
    typeof state.blocker === "string" &&
    state.blocker.startsWith("workspace_head_mismatch:")
  );
}
