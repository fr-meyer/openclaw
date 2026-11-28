import { describe, expect, it, vi } from "vitest";
import { dispatchAndStartWorkboardCards } from "./dispatcher.js";
import { createWorkboardLiveExecutionTracker } from "./live-execution.js";
import { createWorkboardSqliteTestStore } from "./test/sqlite-store.js";

describe("Workboard persisted live execution binding", () => {
  it.each(["pending", "settled"] as const)(
    "binds a worker already %s at persistence",
    async (initialState) => {
      const store = createWorkboardSqliteTestStore();
      const card = await store.create({
        title: "Synthetic worker",
        status: "ready",
        workspaceAccess: { unrestricted: true },
      });
      const liveExecutions = createWorkboardLiveExecutionTracker();
      let state: "pending" | "settled" = initialState;
      const run = vi.fn(async () => ({
        runId: "accepted-worker",
        execution: { observeSettlement: () => state },
      }));
      await dispatchAndStartWorkboardCards({
        store,
        subagent: { run },
        liveExecutions,
        options: { cardId: card.id, now: 10, maxStarts: 1 },
      });
      const accepted = (await store.get(card.id))!;
      expect(liveExecutions.observe(accepted)).toMatchObject({
        producerState: initialState,
        resourceFencing: "unknown",
        releaseAuthorized: false,
      });
      state = "settled";
      expect(liveExecutions.observe(accepted).producerState).toBe("settled");
      const replacement = structuredClone(accepted);
      replacement.metadata!.claim!.claimedAt += 1;
      expect(liveExecutions.observe(replacement).producerState).toBe("unknown");
      expect(liveExecutions.observe(accepted).producerState).toBe("settled");
      liveExecutions.stop();
      expect(liveExecutions.observe(accepted).producerState).toBe("unknown");
    },
  );

  it.each(["rejected", "exception"] as const)(
    "keeps an accepted worker unbound when persistence is %s",
    async (failure) => {
      const store = createWorkboardSqliteTestStore();
      const card = await store.create({
        title: "Synthetic worker",
        status: "ready",
        workspaceAccess: { unrestricted: true },
      });
      vi.spyOn(store, "acceptExecutionLaunch").mockImplementation(async () => {
        if (failure === "exception") {
          throw new Error("write failed");
        }
        return undefined;
      });
      const observeSettlement = vi.fn(() => "settled" as const);
      const liveExecutions = createWorkboardLiveExecutionTracker();
      const result = await dispatchAndStartWorkboardCards({
        store,
        liveExecutions,
        subagent: {
          run: vi.fn(async () => ({
            runId: "accepted-worker",
            execution: { observeSettlement },
          })),
        },
        options: { cardId: card.id, now: 10, maxStarts: 1 },
      });
      expect(result.started).toHaveLength(1);
      const retained = (await store.get(card.id))!;
      expect(retained.metadata?.claim).toBeDefined();
      expect(liveExecutions.observe(retained).producerState).toBe("unknown");
      expect(observeSettlement).not.toHaveBeenCalled();
    },
  );
});
