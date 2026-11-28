import { isRecord } from "@openclaw/normalization-core/record-coerce";
import type { OpenClawConfig } from "../config/types.openclaw.js";
import { parseAgentSessionKey, isIncognitoSessionKey } from "../routing/session-key.js";

export function configuredManagedFlowOwners(
  config: OpenClawConfig,
  pluginId: string,
  boundSessionKey: string,
  allowBoundFallback = true,
): string[] {
  const entry = config.plugins?.entries?.[pluginId]?.config;
  if (!isRecord(entry)) {
    return allowBoundFallback ? [boundSessionKey] : [];
  }
  if (entry.ownerSessionKey != null && typeof entry.ownerSessionKey !== "string") {
    throw new Error("Configured controller owner key is malformed");
  }
  const keys: string[] = [];
  const add = (candidate: unknown) => {
    if (typeof candidate === "string" && candidate && !keys.includes(candidate)) {
      keys.push(candidate);
    }
  };
  add(entry.ownerSessionKey);
  if (
    !Array.isArray(entry.legacyOwnerSessionKeys) &&
    entry.legacyOwnerSessionKeys !== undefined &&
    entry.legacyOwnerSessionKeys !== null
  ) {
    throw new Error("Configured controller owner roster is malformed");
  }
  for (const candidate of Array.isArray(entry.legacyOwnerSessionKeys)
    ? entry.legacyOwnerSessionKeys
    : []) {
    if (typeof candidate !== "string") {
      throw new Error("Configured controller legacy owner key is malformed");
    }
    add(candidate);
  }
  if (entry.repositories != null && !isRecord(entry.repositories)) {
    throw new Error("Configured controller repository owner roster is malformed");
  }
  for (const policy of Object.values(isRecord(entry.repositories) ? entry.repositories : {})) {
    if (
      !isRecord(policy) ||
      (policy.ownerSessionKey != null && typeof policy.ownerSessionKey !== "string")
    ) {
      throw new Error("Configured controller repository owner key is malformed");
    }
    add(policy.ownerSessionKey);
  }
  if (keys.length === 0) {
    return allowBoundFallback ? [boundSessionKey] : [];
  }
  if (
    keys.length > 64 ||
    !keys.includes(boundSessionKey) ||
    keys.some(
      (key) => key !== key.trim() || !parseAgentSessionKey(key) || isIncognitoSessionKey(key),
    )
  ) {
    throw new Error("Configured controller owner roster is not a canonical bound set");
  }
  return keys;
}

export function configuredStatusAgentIds(config: OpenClawConfig, pluginId: string): string[] {
  const entry = config.plugins?.entries?.[pluginId]?.config;
  if (!isRecord(entry) || entry.statusAgentIds == null) {
    return [];
  }
  if (
    !Array.isArray(entry.statusAgentIds) ||
    entry.statusAgentIds.length > 32 ||
    entry.statusAgentIds.some((id) => typeof id !== "string" || !/^[A-Za-z0-9_.-]+$/u.test(id))
  ) {
    throw new Error("Configured controller status-agent roster is malformed");
  }
  return entry.statusAgentIds;
}

/** Observe only native rows still claimed by this controller's exact owner. */
export function isClaimedManagedFlowNativeRun(
  run: unknown,
  flows: readonly unknown[],
  ownerKey: string,
  controllerId: string,
): boolean {
  if (
    !isRecord(run) ||
    run.observationSource !== "native-subagent" ||
    run.label !== `plugin:${controllerId.replace(/\/v1$/, "")}` ||
    run.requesterSessionKey !== ownerKey ||
    typeof run.childSessionKey !== "string" ||
    typeof run.runId !== "string" ||
    typeof run.id !== "string" ||
    !Number.isSafeInteger(run.generation) ||
    (run.generation as number) < 1
  ) {
    return false;
  }
  return flows.some((flow) => {
    if (
      !isRecord(flow) ||
      flow.ownerKey !== ownerKey ||
      flow.controllerId !== controllerId ||
      !isRecord(flow.stateJson)
    ) {
      return false;
    }
    return [flow.stateJson.activeWorker, flow.stateJson.orphanedWorker].some(
      (claim) =>
        isRecord(claim) &&
        claim.sessionKey === run.childSessionKey &&
        claim.runId === run.runId &&
        (claim.taskId == null || claim.taskId === run.id) &&
        claim.nativeGeneration === run.generation,
    );
  });
}

/**
 * Released controller compatibility uses the existing shared-state actor and normal
 * subagent owner. It supplies neither canonical Tasks writes nor private TaskFlow launches.
 */
