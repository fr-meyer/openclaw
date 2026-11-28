import type { WorkboardLaunchState } from "@openclaw/workboard-contract";
import {
  isRecord,
  normalizeBoundedOptionalString,
} from "openclaw/plugin-sdk/string-coerce-runtime";

function normalizeLaunchTimestamp(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) && value >= 0
    ? Math.trunc(value)
    : undefined;
}

export function normalizeLaunchClaimGeneration(value: unknown): number | undefined {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0 ? value : undefined;
}

export function normalizeLaunchState(value: unknown): WorkboardLaunchState | undefined {
  if (!isRecord(value)) {
    return undefined;
  }
  const requestedSessionKey = normalizeBoundedOptionalString(value.requestedSessionKey, 240);
  const provisionalRunId = normalizeBoundedOptionalString(value.provisionalRunId, 160);
  const preparedAt = normalizeLaunchTimestamp(value.preparedAt);
  if (!requestedSessionKey || !provisionalRunId || preparedAt === undefined) {
    return undefined;
  }
  const claimOwnerId = normalizeBoundedOptionalString(value.claimOwnerId, 120);
  const claimGeneration = normalizeLaunchClaimGeneration(value.claimGeneration);
  if (
    (Object.hasOwn(value, "claimOwnerId") || Object.hasOwn(value, "claimGeneration")) &&
    (!claimOwnerId || claimGeneration === undefined)
  ) {
    return undefined;
  }
  const identity = {
    requestedSessionKey,
    provisionalRunId,
    preparedAt,
    ...(claimOwnerId && claimGeneration !== undefined ? { claimOwnerId, claimGeneration } : {}),
  };
  if (value.phase === "prepared") {
    return { phase: "prepared", ...identity };
  }
  if (value.phase === "accepted") {
    const acceptedAt = normalizeLaunchTimestamp(value.acceptedAt);
    const acceptedSessionKey = normalizeBoundedOptionalString(value.acceptedSessionKey, 240);
    const acceptedRunId = normalizeBoundedOptionalString(value.acceptedRunId, 160);
    return acceptedAt === undefined || !acceptedSessionKey
      ? undefined
      : {
          phase: "accepted",
          ...identity,
          acceptedAt,
          acceptedSessionKey,
          ...(acceptedRunId ? { acceptedRunId } : {}),
        };
  }
  if (value.phase === "failed") {
    const failedAt = normalizeLaunchTimestamp(value.failedAt);
    const reason = normalizeBoundedOptionalString(value.reason, 800);
    return failedAt === undefined || !reason
      ? undefined
      : { phase: "failed", ...identity, failedAt, reason };
  }
  return undefined;
}
