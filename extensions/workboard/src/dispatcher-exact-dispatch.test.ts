// Exact-card Workboard worker admission and isolation.
import { describe, expect, it, vi } from "vitest";
import { dispatchAndStartWorkboardCards } from "./dispatcher.js";
import { createWorkboardSqliteTestStore } from "./test/sqlite-store.js";

describe("Workboard exact dispatch", () => {
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
});
