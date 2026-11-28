// Exact-card Workboard worker admission and isolation.
import { describe, expect, it, vi } from "vitest";
import { dispatchAndStartWorkboardCards } from "./dispatcher.js";
import { createKernelStores } from "./test/sqlite-kernel.js";
import {
  createWorkboardSqliteTestHarness,
  createWorkboardSqliteTestStore,
} from "./test/sqlite-store.js";

type DispatchOptions = NonNullable<Parameters<typeof dispatchAndStartWorkboardCards>[0]["options"]>;
const intentRunId = `wb-${"a".repeat(40)}`;

describe("Workboard exact dispatch", () => {
  it.each(["dispatch", "start"] as const)(
    "sends only the exact card and completed parent context in %s mode",
    async (targetMode) => {
      const { store, stores } = createWorkboardSqliteTestHarness({
        createStores: createKernelStores,
      });
      const now = Date.now();
      const parent = await store.create({
        title: "Completed parent sentinel",
        status: "done",
        agentId: "same-agent",
        boardId: "ops",
        metadata: { automation: { summary: "Parent result sentinel" } },
      });
      const unrelated = await store.create({
        title: "Unrelated same-agent sentinel",
        status: "done",
        agentId: "same-agent",
        boardId: "ops",
        metadata: { automation: { summary: "Unrelated result sentinel" } },
      });
      const urgent = await store.create({
        title: "Urgent neighbor",
        status: "ready",
        priority: "urgent",
        boardId: "ops",
        workspaceAccess: { unrestricted: true },
      });
      const stale = await store.create({
        title: "Stale scheduled neighbor",
        status: "scheduled",
        scheduledAt: now - 60_000,
        boardId: "ops",
      });
      const target = await store.create({
        title: "Exact low-priority target",
        status: "ready",
        priority: "low",
        agentId: "same-agent",
        boardId: "ops",
        parents: [parent.id],
        workspaceAccess: { unrestricted: true },
      });
      const beforeUrgent = await store.get(urgent.id);
      const beforeStale = await store.get(stale.id);
      const list = vi.spyOn(store, "list").mockRejectedValue(new Error("unexpected queue scan"));
      const readEntries = stores.cards.entries.bind(stores.cards);
      const entries = vi.spyOn(stores.cards, "entries");
      entries.mockImplementation(async (scope) => {
        if (!scope || (scope.kind === "worker-context" && scope.agentId)) {
          throw new Error("broad worker-context query refused");
        }
        return readEntries(scope);
      });
      const run = vi.fn().mockResolvedValue({ runId: "exact-target-run" });

      const result = await dispatchAndStartWorkboardCards({
        store,
        subagent: { run },
        options: { cardId: target.id, targetMode, maxStarts: 1, now },
      });

      expect(result.started).toEqual([expect.objectContaining({ cardId: target.id })]);
      expect(result.startFailures).toEqual([]);
      expect(run).toHaveBeenCalledTimes(1);
      const message = run.mock.calls[0]?.[0].message as string;
      expect(message).toContain("Completed parent sentinel: Parent result sentinel");
      expect(message).not.toContain(unrelated.title);
      expect(message).not.toContain("Unrelated result sentinel");
      expect(message).not.toContain("## Recent done work by same-agent");
      expect(message).not.toContain("Urgent neighbor");
      expect(message).not.toContain("Stale scheduled neighbor");
      expect(list).not.toHaveBeenCalled();
      // Main uses direct parent lookups, not even a scoped entries query.
      expect(entries).not.toHaveBeenCalled();
      await expect(store.get(urgent.id)).resolves.toEqual(beforeUrgent);
      await expect(store.get(stale.id)).resolves.toEqual(beforeStale);
    },
  );

  it("keeps recent same-agent work in scheduled batch context", async () => {
    const store = createWorkboardSqliteTestStore();
    await store.create({
      title: "Batch context sentinel",
      status: "done",
      agentId: "batch-agent",
      boardId: "ops",
      metadata: { automation: { summary: "Batch result sentinel" } },
    });
    const target = await store.create({
      title: "Batch target",
      status: "ready",
      agentId: "batch-agent",
      boardId: "ops",
      workspaceAccess: { unrestricted: true },
    });
    const run = vi.fn().mockResolvedValue({ runId: "batch-run" });

    const result = await dispatchAndStartWorkboardCards({
      store,
      subagent: { run },
      options: { boardId: "ops", maxStarts: 1 },
    });

    expect(result.started).toEqual([expect.objectContaining({ cardId: target.id })]);
    expect(run).toHaveBeenCalledTimes(1);
    const message = run.mock.calls[0]?.[0].message as string;
    expect(message).toContain("Batch context sentinel: Batch result sentinel");
  });

  it("dispatches one exact queued card without enumerating or mutating unrelated ready or stale cards", async () => {
    vi.useFakeTimers();
    try {
      vi.setSystemTime(1_000_000);
      const store = createWorkboardSqliteTestStore();
      const stale = await store.create({
        title: "Expired unrelated worker",
        status: "ready",
        boardId: "ops",
        agentId: "expired-owner",
      });
      await store.claim(stale.id, {
        ownerId: "expired-owner",
        token: "expired-token",
        ttlSeconds: 1,
      });
      const urgent = await store.create({
        title: "Unrelated urgent card",
        status: "ready",
        priority: "urgent",
        boardId: "ops",
        agentId: "urgent-owner",
        workspaceAccess: { unrestricted: true },
      });
      const target = await store.create({
        title: "Exact queued target",
        status: "ready",
        priority: "low",
        boardId: "ops",
        agentId: "target-owner",
        workspaceAccess: { unrestricted: true },
      });
      vi.setSystemTime(1_000_000 + 10 * 60 * 1000);
      const staleBefore = await store.get(stale.id);
      const urgentBefore = await store.get(urgent.id);
      const list = vi.spyOn(store, "list");
      const run = vi.fn().mockResolvedValue({ runId: "target-run" });

      const result = await dispatchAndStartWorkboardCards({
        store,
        subagent: { run },
        options: {
          cardId: target.id,
          targetMode: "dispatch",
          boardId: "ops",
          maxStarts: 1,
          now: Date.now(),
        },
      });

      expect(list).not.toHaveBeenCalled();
      expect(result.startFailures).toEqual([]);
      expect(run).toHaveBeenCalledOnce();
      expect(result.started).toEqual([
        expect.objectContaining({ cardId: target.id, runId: "target-run" }),
      ]);
      expect(result.started[0]).not.toHaveProperty("card");
      await expect(store.get(target.id)).resolves.toMatchObject({
        status: "running",
        metadata: { claim: { ownerId: "target-owner" } },
      });
      await expect(store.get(stale.id)).resolves.toEqual(staleBefore);
      await expect(store.get(urgent.id)).resolves.toEqual(urgentBefore);
    } finally {
      vi.useRealTimers();
    }
  });

  it("keeps dependency-gated exact dispatch targets out of worker admission", async () => {
    const store = createWorkboardSqliteTestStore();
    const parent = await store.create({ title: "Incomplete parent", status: "todo" });
    const target = await store.create({
      title: "Dependency-gated target",
      status: "todo",
      agentId: "target-owner",
      workspaceAccess: { unrestricted: true },
    });
    await store.linkCards(parent.id, target.id);
    const run = vi.fn();

    const result = await dispatchAndStartWorkboardCards({
      store,
      subagent: { run },
      options: { cardId: target.id, targetMode: "dispatch", maxStarts: 1 },
    });

    expect(run).not.toHaveBeenCalled();
    expect(result.started).toEqual([]);
    expect(result.startFailures).toEqual([
      expect.objectContaining({
        cardId: target.id,
        error: expect.stringMatching(/dependency.*ready/i),
      }),
    ]);
    await expect(store.get(target.id)).resolves.toMatchObject({ status: "todo" });
  });
  it.each([
    { name: "no card", options: { intentRunId } },
    {
      name: "target mode without card",
      options: { cardId: undefined, targetMode: "dispatch" },
    },
    { name: "manual start", options: { targetMode: "start", intentRunId } },
    { name: "malformed intent", options: { targetMode: "dispatch", intentRunId: "invalid" } },
    {
      name: "uppercase intent",
      options: { targetMode: "dispatch", intentRunId: `wb-${"A".repeat(40)}` },
    },
    {
      name: "trailing newline",
      options: { targetMode: "dispatch", intentRunId: `${intentRunId}\n` },
    },
    { name: "multiple starts", options: { targetMode: "dispatch", maxStarts: 2 } },
  ] satisfies Array<{ name: string; options: DispatchOptions }>)(
    "rejects $name before changing a card or launching work",
    async (scenario) => {
      const store = createWorkboardSqliteTestStore();
      const target = await store.create({ title: "Unchanged exact target", status: "ready" });
      const before = await store.get(target.id);
      const run = vi.fn();

      await expect(
        dispatchAndStartWorkboardCards({
          store,
          subagent: { run },
          options: {
            ...(scenario.name === "no card" ? {} : { cardId: target.id }),
            ...scenario.options,
          },
        }),
      ).rejects.toThrow();

      expect(run).not.toHaveBeenCalled();
      await expect(store.get(target.id)).resolves.toEqual(before);
    },
  );
});
