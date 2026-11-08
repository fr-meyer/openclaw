import { createHash } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import { dispatchAndStartWorkboardCards } from "./dispatcher.js";
import { createKernelStores } from "./test/sqlite-kernel.js";
import {
  createWorkboardSqliteTestHarness,
  createWorkboardSqliteTestStore,
} from "./test/sqlite-store.js";

type DispatchOptions = NonNullable<Parameters<typeof dispatchAndStartWorkboardCards>[0]["options"]>;

const intentRunId = `wb-${"a".repeat(40)}`;

describe("exact-card dispatch", () => {
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
      expect(entries).toHaveBeenCalledWith(
        expect.objectContaining({ kind: "worker-context", cardId: target.id, agentId: undefined }),
      );
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

  it("starts only the selected ready card and binds the run to its intent", async () => {
    const store = createWorkboardSqliteTestStore();
    const neighbor = await store.create({
      title: "Urgent neighboring card",
      status: "ready",
      priority: "urgent",
      workspaceAccess: { unrestricted: true },
    });
    const target = await store.create({
      title: "Exact low-priority card",
      status: "ready",
      priority: "low",
      workspaceAccess: { unrestricted: true },
    });
    const beforeNeighbor = await store.get(neighbor.id);
    const list = vi.spyOn(store, "list").mockRejectedValue(new Error("unexpected queue scan"));
    const run = vi.fn().mockResolvedValue({ runId: "accepted-target-run" });

    const result = await dispatchAndStartWorkboardCards({
      store,
      subagent: { run },
      options: { cardId: target.id, targetMode: "dispatch", intentRunId, maxStarts: 1 },
    });

    expect(result.started).toEqual([
      expect.objectContaining({ cardId: target.id, runId: "accepted-target-run" }),
    ]);
    expect(result.startFailures).toEqual([]);
    const expectedRunId = `workboard:intent:${createHash("sha256")
      .update(target.id)
      .update("\0")
      .update(intentRunId)
      .digest("hex")}`;
    expect(run).toHaveBeenCalledExactlyOnceWith(
      expect.objectContaining({ idempotencyKey: expectedRunId }),
    );
    expect(list).not.toHaveBeenCalled();
    await expect(store.get(neighbor.id)).resolves.toEqual(beforeNeighbor);
    await expect(store.get(target.id)).resolves.toMatchObject({
      metadata: { automation: { launch: { phase: "accepted", provisionalRunId: expectedRunId } } },
    });
  });

  it.each(["backlog", "todo", "blocked", "review", "done"] as const)(
    "does not turn exact dispatch into a manual start from %s",
    async (status) => {
      const store = createWorkboardSqliteTestStore();
      const target = await store.create({
        title: `Exact ${status}`,
        status,
        workspaceAccess: { unrestricted: true },
      });
      const before = await store.get(target.id);
      const run = vi.fn();

      const result = await dispatchAndStartWorkboardCards({
        store,
        subagent: { run },
        options: { cardId: target.id, targetMode: "dispatch", maxStarts: 1 },
      });

      expect(result.started).toEqual([]);
      expect(result.startFailures).toEqual([
        expect.objectContaining({ cardId: target.id, error: expect.stringContaining(status) }),
      ]);
      expect(run).not.toHaveBeenCalled();
      await expect(store.get(target.id)).resolves.toEqual(before);
    },
  );

  it.each([
    { label: "due", offset: -1_000, starts: true },
    { label: "future", offset: 60_000, starts: false },
  ])("honors the $label target's schedule without dispatching its neighbor", async (scenario) => {
    const store = createWorkboardSqliteTestStore();
    const now = Date.now();
    const target = await store.create({
      title: "Scheduled exact target",
      status: "scheduled",
      scheduledAt: now + scenario.offset,
      workspaceAccess: { unrestricted: true },
    });
    const neighbor = await store.create({
      title: "Due neighboring card",
      status: "scheduled",
      scheduledAt: now - 1_000,
    });
    const beforeNeighbor = await store.get(neighbor.id);
    const run = vi.fn().mockResolvedValue({ runId: "scheduled-target-run" });

    const result = await dispatchAndStartWorkboardCards({
      store,
      subagent: { run },
      options: { cardId: target.id, targetMode: "dispatch", maxStarts: 1, now },
    });

    expect(run).toHaveBeenCalledTimes(scenario.starts ? 1 : 0);
    expect(result.started).toHaveLength(scenario.starts ? 1 : 0);
    expect(result.startFailures).toHaveLength(scenario.starts ? 0 : 1);
    await expect(store.get(neighbor.id)).resolves.toEqual(beforeNeighbor);
  });

  it("retains the manual start behavior for an explicit start target", async () => {
    const store = createWorkboardSqliteTestStore();
    const target = await store.create({
      title: "Manual start target",
      status: "todo",
      workspaceAccess: { unrestricted: true },
    });
    const run = vi.fn().mockResolvedValue({ runId: "manual-start-run" });

    const result = await dispatchAndStartWorkboardCards({
      store,
      subagent: { run },
      options: { cardId: target.id, targetMode: "start", maxStarts: 1 },
    });

    expect(result.started).toEqual([expect.objectContaining({ cardId: target.id })]);
    expect(result.startFailures).toEqual([]);
  });

  it("keeps atomic owner capacity across boards without reading the queue", async () => {
    const store = createWorkboardSqliteTestStore();
    const active = await store.create({
      title: "Active owner",
      status: "ready",
      boardId: "ops",
      agentId: "shared-owner",
    });
    await store.claim(active.id, { ownerId: "shared-owner" });
    const target = await store.create({
      title: "Blocked exact target",
      status: "ready",
      boardId: "product",
      agentId: "shared-owner",
      workspaceAccess: { unrestricted: true },
    });
    const list = vi.spyOn(store, "list").mockRejectedValue(new Error("unexpected queue scan"));
    const run = vi.fn();

    const result = await dispatchAndStartWorkboardCards({
      store,
      subagent: { run },
      options: { cardId: target.id, targetMode: "dispatch", maxStarts: 1 },
    });

    expect(result.startFailures).toEqual([
      expect.objectContaining({
        cardId: target.id,
        error: expect.stringContaining("shared-owner"),
      }),
    ]);
    expect(run).not.toHaveBeenCalled();
    expect(list).not.toHaveBeenCalled();
    await expect(store.get(target.id)).resolves.toMatchObject({ status: "ready" });
  });

  it.each([
    { name: "no card", options: { intentRunId } },
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
