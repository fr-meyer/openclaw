// Workboard plugin module implements serialized dispatch bookkeeping and recovery.
import { randomUUID } from "node:crypto";
import type { WorkboardBoardMetadata, WorkboardCard } from "@openclaw/workboard-contract";
import {
  cardBoardId,
  closeRunningAttempts,
  isDependencyPromotableStatus,
  latestRunningAttempt,
  retryBudgetExhausted,
} from "./store-card-helpers.js";
import {
  isWorkboardClaimReclaimable,
  MAX_CARD_NOTIFICATIONS,
  secondsToDurationMs,
} from "./store-constants.js";
import type { WorkboardDispatchOptions, WorkboardDispatchResult } from "./store-inputs.js";
import { normalizeBoardId, normalizeTimestamp } from "./store-normalizers.js";
import { WorkboardNotificationStore } from "./store-notifications.js";

export class WorkboardDispatchStore extends WorkboardNotificationStore {
  private async getAutoOrchestrationBoard(
    card: WorkboardCard,
  ): Promise<WorkboardBoardMetadata | undefined> {
    if (
      card.status !== "triage" ||
      card.metadata?.archivedAt ||
      card.metadata?.workerProtocol?.state === "idle"
    ) {
      return undefined;
    }
    const board = await this.boardStore.lookup(cardBoardId(card));
    return board?.version === 1 && board.board.orchestration?.autoDecompose === true
      ? board.board
      : undefined;
  }

  async dispatch(
    input: number | WorkboardDispatchOptions = Date.now(),
  ): Promise<WorkboardDispatchResult> {
    const now = typeof input === "number" ? input : normalizeTimestamp(input.now, Date.now());
    const boardId = typeof input === "number" ? undefined : normalizeBoardId(input.boardId);
    const assertOwnerCurrent = typeof input === "number" ? undefined : input.assertOwnerCurrent;
    const rawCardId = typeof input === "number" ? undefined : input.cardId;
    const cardId = typeof rawCardId === "string" ? rawCardId.trim() : undefined;
    if (rawCardId !== undefined && !cardId) {
      throw new Error("cardId must be a non-empty string.");
    }
    return await this.enqueueMutation(async () => {
      const promoted: WorkboardCard[] = [];
      const reclaimed: WorkboardCard[] = [];
      const blocked: WorkboardCard[] = [];
      const orchestrated: WorkboardCard[] = [];
      const orchestratedByBoard = new Map<string, number>();
      let cards: WorkboardCard[];
      if (cardId) {
        const card = await this.get(cardId);
        if (!card) {
          throw new Error(`card not found: ${cardId}`);
        }
        const actualBoardId = cardBoardId(card);
        if (boardId && actualBoardId !== boardId) {
          throw new Error(`card ${cardId} belongs to board ${actualBoardId}, not ${boardId}.`);
        }
        cards = [card];
      } else {
        cards = await this.list({ boardId });
      }
      for (const card of cards) {
        // Archived cards remain readable and restorable, but must never re-enter automation.
        if (card.metadata?.archivedAt) {
          continue;
        }
        await this.withMutationAuthority(async () => {
          let latest = await this.promoteDependencyReady(card.id, now);
        const wasPromoted = latest.status !== card.status;
        const claim = latest.metadata?.claim;
        const latestAttempt = latestRunningAttempt(latest);
        const maxRuntimeSeconds = latest.metadata?.automation?.maxRuntimeSeconds;
        const runtimeStartedAt = latestAttempt?.startedAt ?? claim?.claimedAt ?? latest.startedAt;
        const timedOut =
          Boolean(maxRuntimeSeconds && runtimeStartedAt) &&
          now - runtimeStartedAt! > secondsToDurationMs(maxRuntimeSeconds!);
        const claimExpired = isWorkboardClaimReclaimable(claim, now);
        const retriesExhausted = retryBudgetExhausted(latest);
        if (latest.status === "running" && (timedOut || claimExpired)) {
          const reason = timedOut
            ? "Run exceeded the card max runtime."
            : "Claim expired without a recent heartbeat.";
          const execution =
            latest.execution?.status === "running"
              ? { ...latest.execution, status: "blocked" as const, updatedAt: now }
              : latest.execution;
          latest = await this.updateCard(latest.id, {
            status: "blocked",
            ...(execution ? { execution } : {}),
            metadata: {
              ...latest.metadata,
              claim: undefined,
              attempts: closeRunningAttempts(latest.metadata?.attempts, now, "blocked", reason),
              failureCount: (latest.metadata?.failureCount ?? 0) + 1,
              notifications: [
                ...(latest.metadata?.notifications ?? []),
                {
                  id: randomUUID(),
                  kind: "failed" as const,
                  createdAt: now,
                  sequence: this.nextNotificationSequence(now),
                  message: reason,
                },
              ].slice(-MAX_CARD_NOTIFICATIONS),
            },
          });
          blocked.push(latest);
        } else if (claimExpired) {
          latest = await this.updateCard(latest.id, {
            metadata: { ...latest.metadata, claim: undefined },
          });
          reclaimed.push(latest);
        }
        if (
          !latest.metadata?.claim &&
          retriesExhausted &&
          isDependencyPromotableStatus(latest.status)
        ) {
          latest = await this.updateCard(latest.id, {
            status: "blocked",
            metadata: {
              ...latest.metadata,
              notifications: [
                ...(latest.metadata?.notifications ?? []),
                {
                  id: randomUUID(),
                  kind: "failed" as const,
                  createdAt: now,
                  sequence: this.nextNotificationSequence(now),
                  message: "Card exhausted its retry budget.",
                },
              ].slice(-MAX_CARD_NOTIFICATIONS),
            },
          });
          blocked.push(latest);
        }
        const orchestrationBoard = await this.getAutoOrchestrationBoard(latest);
        if (orchestrationBoard) {
          const latestBoardId = cardBoardId(latest);
          const cap = orchestrationBoard.orchestration?.autoDecomposePerDispatch ?? 3;
          const boardCount = orchestratedByBoard.get(latestBoardId) ?? 0;
          if (boardCount < cap) {
            latest = await this.recordOrchestrationCandidate(latest, now);
            orchestrated.push(latest);
            orchestratedByBoard.set(latestBoardId, boardCount + 1);
          }
        }
        if (wasPromoted && latest.status !== "blocked") {
          promoted.push(latest);
        }
        if (cardId) {
          // Account the explicit request before worker admission. A later Gateway launch
          // failure is still an attempted dispatch, while broad idle sweeps stay read-only.
          await this.updateCard(latest.id, {
            metadata: {
              ...latest.metadata,
              automation: {
                ...latest.metadata?.automation,
                dispatchCount: (latest.metadata?.automation?.dispatchCount ?? 0) + 1,
                lastDispatchAt: now,
              },
            },
          });
        }
        }, assertOwnerCurrent);
      }
      return {
        promoted,
        reclaimed,
        blocked,
        orchestrated,
        count: promoted.length + reclaimed.length + blocked.length + orchestrated.length,
      };
    });
  }
}
