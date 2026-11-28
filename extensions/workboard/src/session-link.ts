import type {
  WorkboardCard,
  WorkboardClaim,
  WorkboardLaunchState,
} from "@openclaw/workboard-contract";
import { cardBoardId, cardRunId, cardSessionKey } from "./store-card-helpers.js";

export function claimMatchesLaunch(
  claim: WorkboardClaim | undefined,
  launch: WorkboardLaunchState | undefined,
): boolean {
  if (!claim || !launch) {
    return false;
  }
  if (launch.claimGeneration !== undefined) {
    return claim.ownerId === launch.claimOwnerId && claim.claimedAt === launch.claimGeneration;
  }
  // Preserve launches written before the claim snapshot was introduced.
  return claim.claimedAt <= launch.preparedAt;
}

export function claimConflictsWithLaunch(
  claim: WorkboardClaim | undefined,
  launch: WorkboardLaunchState | undefined,
): boolean {
  return Boolean(claim && launch && !claimMatchesLaunch(claim, launch));
}

function sanitizeSessionSegment(value: string | undefined, fallback: string): string {
  const sanitized = (value ?? fallback)
    .trim()
    .replace(/[^a-zA-Z0-9_-]/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-|-$/g, "");
  return (sanitized || fallback).slice(0, 96);
}

export function workboardSessionKeyForCard(card: WorkboardCard): string {
  const boardId = sanitizeSessionSegment(cardBoardId(card), "default");
  const cardId = sanitizeSessionSegment(card.id, "card");
  const suffix = `subagent:workboard-${boardId}-${cardId}`;
  return card.agentId ? `agent:${sanitizeSessionSegment(card.agentId, "agent")}:${suffix}` : suffix;
}

function sessionKeyMatchesCard(candidate: string, cardKey: string): boolean {
  return (
    candidate === cardKey ||
    (cardKey.startsWith("subagent:workboard-") && candidate.endsWith(`:${cardKey}`))
  );
}

export function workboardCardMatchesLifecycleLink(
  card: WorkboardCard,
  source: { sessionKey?: string; runId?: string },
): boolean {
  const linkedSessionKey = cardSessionKey(card);
  const sessionMatches = Boolean(
    source.sessionKey &&
    (linkedSessionKey
      ? sessionKeyMatchesCard(source.sessionKey, linkedSessionKey)
      : sessionKeyMatchesCard(source.sessionKey, workboardSessionKeyForCard(card))),
  );
  const linkedRunId = cardRunId(card);
  if (linkedRunId && source.runId) {
    if (source.runId !== linkedRunId) {
      const launch = card.metadata?.automation?.launch;
      const sourceBelongsToPriorAttempt = card.metadata?.attempts?.some(
        (attempt) => attempt.runId === source.runId && attempt.runId !== linkedRunId,
      );
      const mayBackfillProvisionalRun =
        !sourceBelongsToPriorAttempt &&
        launch?.provisionalRunId === linkedRunId &&
        (launch.phase === "prepared" ||
          (launch.phase === "accepted" && launch.acceptedRunId === undefined));
      if (!mayBackfillProvisionalRun) {
        return false;
      }
    }
    return linkedSessionKey && source.sessionKey ? sessionMatches : true;
  }
  return sessionMatches;
}

export function workboardCardSessionLookupKey(card: WorkboardCard): string {
  return cardSessionKey(card) ?? workboardSessionKeyForCard(card);
}
