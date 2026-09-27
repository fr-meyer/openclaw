import type { WorkboardCard, WorkboardLaunchState } from "@openclaw/workboard-contract";
import type { PluginRuntime } from "openclaw/plugin-sdk/plugin-runtime";
import { MAX_CARDS } from "./store-constants.js";

type Execution = NonNullable<Awaited<ReturnType<PluginRuntime["subagent"]["run"]>>["execution"]>;
type AcceptedLaunch = Extract<WorkboardLaunchState, { phase: "accepted" }>;
type Binding = { launch: AcceptedLaunch; execution: Execution };

function matchesLaunch(card: WorkboardCard, expected: AcceptedLaunch): boolean {
  const launch = card.metadata?.automation?.launch;
  const claim = card.metadata?.claim;
  return (
    launch?.phase === "accepted" &&
    launch.requestedSessionKey === expected.requestedSessionKey &&
    launch.provisionalRunId === expected.provisionalRunId &&
    launch.preparedAt === expected.preparedAt &&
    launch.claimOwnerId === expected.claimOwnerId &&
    launch.claimGeneration === expected.claimGeneration &&
    launch.acceptedAt === expected.acceptedAt &&
    launch.acceptedRunId === expected.acceptedRunId &&
    launch.acceptedSessionKey === expected.acceptedSessionKey &&
    card.runId === expected.acceptedRunId &&
    card.sessionKey === expected.acceptedSessionKey &&
    card.execution?.runId === expected.acceptedRunId &&
    card.execution?.sessionKey === expected.acceptedSessionKey &&
    (!claim ||
      (claim.ownerId === expected.claimOwnerId && claim.claimedAt === expected.claimGeneration))
  );
}

/** Service-owned live evidence; deliberately neither persisted nor release authority. */
export function createWorkboardLiveExecutionTracker() {
  const bindings = new Map<string, Binding>();
  let closed = false;
  return {
    bind: (card: WorkboardCard, execution: Execution) => {
      const launch = card.metadata?.automation?.launch;
      if (
        closed ||
        launch?.phase !== "accepted" ||
        !launch.acceptedRunId ||
        !launch.claimOwnerId ||
        launch.claimGeneration === undefined ||
        !matchesLaunch(card, launch)
      ) {
        return;
      }
      bindings.delete(card.id);
      bindings.set(card.id, { launch: { ...launch }, execution });
      // Card IDs may be deleted and recreated throughout one service lifetime.
      if (bindings.size > MAX_CARDS) {
        const oldest = bindings.keys().next().value;
        if (oldest !== undefined) {
          bindings.delete(oldest);
        }
      }
    },
    observe: (card: WorkboardCard) => {
      const binding = bindings.get(card.id);
      let producerState: ReturnType<Execution["observeSettlement"]> = "unknown";
      if (!closed && binding && matchesLaunch(card, binding.launch)) {
        try {
          producerState = binding.execution.observeSettlement();
        } catch {
          // Retired plugin/Gateway capabilities cannot be reconstituted from stored JSON.
        }
      }
      return {
        cardId: card.id,
        ...(binding && matchesLaunch(card, binding.launch)
          ? {
              runId: binding.launch.acceptedRunId,
              sessionKey: binding.launch.acceptedSessionKey,
              claimOwnerId: binding.launch.claimOwnerId,
              claimGeneration: binding.launch.claimGeneration,
            }
          : {}),
        producerState,
        resourceFencing: "unknown" as const,
        releaseAuthorized: false as const,
      };
    },
    stop: () => {
      closed = true;
      bindings.clear();
    },
  };
}

export type WorkboardLiveExecutionTracker = ReturnType<typeof createWorkboardLiveExecutionTracker>;
