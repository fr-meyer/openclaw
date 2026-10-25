import { createHash } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import { dispatchAndStartWorkboardCards } from "./dispatcher.js";
import { createWorkboardSqliteTestStore } from "./test/sqlite-store.js";

type DispatchOptions = NonNullable<Parameters<typeof dispatchAndStartWorkboardCards>[0]["options"]>;

const intentRunId = `wb-${"a".repeat(40)}`;

describe("exact-card dispatch", () => {
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
