import { createHash } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import { createWorkboardSqliteTestStore } from "./test/sqlite-store.js";

const intentRunId = `wb-${"a".repeat(40)}`;

function expectedIntentRunId(cardId: string, intent: string): string {
  return `workboard:intent:${createHash("sha256")
    .update(cardId)
    .update("\0")
    .update(intent)
    .digest("hex")}`;
}

describe("targeted store dispatch", () => {
  it("orchestrates only its exact target and never enumerates neighboring cards", async () => {
    const store = createWorkboardSqliteTestStore();
    await store.upsertBoard({ id: "ops", orchestration: { autoDecompose: true } });
    const target = await store.create({ title: "Target triage", status: "triage", boardId: "ops" });
    const neighbor = await store.create({
      title: "Other triage",
      status: "triage",
      boardId: "ops",
    });
    const beforeNeighbor = await store.get(neighbor.id);
    const list = vi.spyOn(store, "list").mockRejectedValue(new Error("unexpected queue scan"));

    const result = await store.dispatch({ cardId: target.id, boardId: "ops", now: 100 });

    expect(result.orchestrated.map((card) => card.id)).toEqual([target.id]);
    expect(result.count).toBe(1);
    expect(list).not.toHaveBeenCalled();
    await expect(store.get(neighbor.id)).resolves.toEqual(beforeNeighbor);
  });

  it("promotes only the selected dependency-ready card", async () => {
    const store = createWorkboardSqliteTestStore();
    const parent = await store.create({ title: "Parent", status: "todo" });
    const target = await store.create({ title: "Target", status: "todo", parents: [parent.id] });
    const neighbor = await store.create({
      title: "Neighbor",
      status: "todo",
      parents: [parent.id],
    });
    await store.move(parent.id, "done", 1);
    const beforeNeighbor = await store.get(neighbor.id);
    const list = vi.spyOn(store, "list").mockRejectedValue(new Error("unexpected queue scan"));

    const result = await store.dispatch({ cardId: target.id });

    expect(result.promoted.map((card) => card.id)).toEqual([target.id]);
    await expect(store.get(target.id)).resolves.toMatchObject({ status: "ready" });
    await expect(store.get(neighbor.id)).resolves.toEqual(beforeNeighbor);
    expect(list).not.toHaveBeenCalled();
  });

  it("does not reclaim or time out another card while dispatching its target", async () => {
    const store = createWorkboardSqliteTestStore();
    const active = await store.create({ title: "Unrelated active card", status: "ready" });
    const claimed = await store.claim(active.id, { ownerId: "other-owner", ttlSeconds: 1 });
    const target = await store.create({ title: "Exact ready target", status: "ready" });
    const beforeActive = await store.get(active.id);

    const result = await store.dispatch({
      cardId: target.id,
      now: claimed.card.metadata!.claim!.expiresAt! + 60_000,
    });

    expect(result).toEqual({
      promoted: [],
      reclaimed: [],
      blocked: [],
      orchestrated: [],
      count: 0,
    });
    await expect(store.get(active.id)).resolves.toEqual(beforeActive);
  });

  it.each([
    { name: "blank target", cardId: " " },
    { name: "non-string target", cardId: 1 },
    { name: "missing target", cardId: "missing" },
    { name: "wrong board", cardId: "target", boardId: "product" },
  ])("rejects $name before changing cards", async (scenario) => {
    const store = createWorkboardSqliteTestStore();
    await store.upsertBoard({ id: "ops", orchestration: { autoDecompose: true } });
    await store.upsertBoard({ id: "product" });
    const target = await store.create({ title: "Target", status: "triage", boardId: "ops" });
    const before = await store.get(target.id);
    const list = vi.spyOn(store, "list").mockRejectedValue(new Error("unexpected queue scan"));

    await expect(
      store.dispatch({
        cardId: scenario.cardId === "target" ? target.id : scenario.cardId,
        ...(scenario.boardId ? { boardId: scenario.boardId } : {}),
      }),
    ).rejects.toThrow();

    await expect(store.get(target.id)).resolves.toEqual(before);
    expect(list).not.toHaveBeenCalled();
  });
});

describe("dispatch intent launch identity", () => {
  it("binds the provisional run to both card and intent without storing the raw intent", async () => {
    const store = createWorkboardSqliteTestStore();
    const first = await store.create({ title: "First", status: "ready" });
    const second = await store.create({ title: "Second", status: "ready" });
    const firstClaim = await store.claim(first.id, { ownerId: "first-owner" });
    const secondClaim = await store.claim(second.id, { ownerId: "second-owner" });
    const firstLaunch = await store.prepareExecutionLaunch(first.id, {
      requestedSessionKey: "first-session",
      now: 100,
      scope: { ownerId: "first-owner", token: firstClaim.token },
      intentRunId,
    });
    const secondLaunch = await store.prepareExecutionLaunch(second.id, {
      requestedSessionKey: "second-session",
      now: 100,
      scope: { ownerId: "second-owner", token: secondClaim.token },
      intentRunId,
    });

    expect(firstLaunch.launch.provisionalRunId).toBe(expectedIntentRunId(first.id, intentRunId));
    expect(secondLaunch.launch.provisionalRunId).toBe(expectedIntentRunId(second.id, intentRunId));
    expect(firstLaunch.launch.provisionalRunId).not.toBe(secondLaunch.launch.provisionalRunId);
    expect(firstLaunch.launch).toMatchObject({
      claimOwnerId: "first-owner",
      claimGeneration: firstClaim.card.metadata?.claim?.claimedAt,
    });
    expect(secondLaunch.launch).toMatchObject({
      claimOwnerId: "second-owner",
      claimGeneration: secondClaim.card.metadata?.claim?.claimedAt,
    });
    expect(JSON.stringify(firstLaunch.card)).not.toContain(intentRunId);
    expect(firstLaunch.launch).not.toHaveProperty("intentRunId");
  });

  it.each(["", "invalid", `wb-${"A".repeat(40)}`, `wb-${"a".repeat(39)}`, `${intentRunId}\n`])(
    "rejects malformed intent %j without replacing the launch",
    async (intent) => {
      const store = createWorkboardSqliteTestStore();
      const card = await store.create({ title: "Unchanged launch", status: "ready" });
      const claimed = await store.claim(card.id, { ownerId: "worker" });
      const before = await store.get(card.id);

      await expect(
        store.prepareExecutionLaunch(card.id, {
          requestedSessionKey: "target-session",
          now: 100,
          scope: { ownerId: "worker", token: claimed.token },
          intentRunId: intent,
        }),
      ).rejects.toThrow("dispatch intent id");

      await expect(store.get(card.id)).resolves.toEqual(before);
    },
  );

  it("preserves owner-or-token launch authorization when an intent is supplied", async () => {
    const store = createWorkboardSqliteTestStore();
    const card = await store.create({ title: "Claimed target", status: "ready" });
    const claimed = await store.claim(card.id, { ownerId: "current-owner" });
    const before = await store.get(card.id);

    await expect(
      store.prepareExecutionLaunch(card.id, {
        requestedSessionKey: "wrong-owner-session",
        now: 100,
        scope: { ownerId: "other-owner", token: "wrong-token" },
        intentRunId,
      }),
    ).rejects.toThrow();

    await expect(store.get(card.id)).resolves.toEqual(before);
    for (const scope of [
      { ownerId: "current-owner" },
      { ownerId: "current-owner", token: "not-the-claim-token" },
      { ownerId: "other-owner", token: claimed.token },
    ]) {
      const prepared = await store.prepareExecutionLaunch(card.id, {
        requestedSessionKey: "authorized-session",
        now: 100,
        scope,
        intentRunId,
      });
      expect(prepared.launch.claimGeneration).toBe(claimed.card.metadata?.claim?.claimedAt);
      expect(prepared.card.metadata?.claim).toEqual(claimed.card.metadata?.claim);
    }
  });

  it("does not let an earlier attempt with the same intent replace a newer prepared launch", async () => {
    const store = createWorkboardSqliteTestStore();
    const card = await store.create({ title: "Retried intent", status: "ready" });
    const firstClaim = await store.claim(card.id, { ownerId: "worker" });
    const first = await store.prepareExecutionLaunch(card.id, {
      requestedSessionKey: "intent-session",
      now: 100,
      scope: { ownerId: "worker", token: firstClaim.token },
      intentRunId,
    });
    await store.failPreparedLaunch(card.id, {
      expectedLaunch: first.launch,
      reason: "First attempt failed before acceptance.",
      failedAt: 101,
    });
    await store.unblock(card.id);
    const replacementClaim = await store.claim(card.id, { ownerId: "worker" });
    const replacement = await store.prepareExecutionLaunch(card.id, {
      requestedSessionKey: "intent-session",
      now: 200,
      scope: { ownerId: "worker", token: replacementClaim.token },
      intentRunId,
    });

    expect(replacement.launch.provisionalRunId).toBe(first.launch.provisionalRunId);
    expect(replacement.launch.preparedAt).toBeGreaterThan(first.launch.preparedAt);
    await expect(
      store.failPreparedLaunch(card.id, {
        expectedLaunch: first.launch,
        reason: "Delayed first failure.",
        failedAt: 201,
      }),
    ).resolves.toBe(false);
    await expect(
      store.acceptExecutionLaunch(card.id, {
        expectedLaunch: first.launch,
        acceptedAt: replacement.launch.preparedAt + 1,
        expectedSessionKey: first.launch.requestedSessionKey,
        expectedRunId: first.launch.provisionalRunId,
        sessionKey: "old-accepted-session",
        runId: "old-accepted-run",
        execution: {
          id: "old-execution",
          kind: "agent-session",
          mode: "autonomous",
          status: "running",
          startedAt: 100,
          updatedAt: 201,
        },
      }),
    ).resolves.toBeUndefined();
    await expect(store.get(card.id)).resolves.toEqual(replacement.card);
  });

  it("rejects prepared acceptance and failure after a same-owner replacement claim", async () => {
    const clock = vi.spyOn(Date, "now").mockReturnValue(10_000);
    try {
      const store = createWorkboardSqliteTestStore();
      const card = await store.create({
        title: "Prepared intent with a replaced claim",
        status: "ready",
      });
      const firstClaim = await store.claim(card.id, { ownerId: "worker", token: "first-token" });
      const prepared = await store.prepareExecutionLaunch(card.id, {
        requestedSessionKey: "same-intent-session",
        now: 10_000,
        scope: { ownerId: "worker", token: firstClaim.token },
        intentRunId,
      });
      await store.releaseClaim(card.id, { ownerId: "worker", token: firstClaim.token });
      const replacement = await store.claim(card.id, {
        ownerId: "worker",
        token: "replacement-token",
      });
      const before = await store.get(card.id);

      expect(replacement.card.metadata?.claim?.claimedAt).toBeGreaterThan(
        prepared.launch.claimGeneration!,
      );
      expect(before?.metadata?.automation?.launch).toEqual(prepared.launch);
      await expect(
        store.acceptExecutionLaunch(card.id, {
          expectedLaunch: prepared.launch,
          expectedSessionKey: prepared.launch.requestedSessionKey,
          expectedRunId: prepared.launch.provisionalRunId,
          acceptedAt: prepared.launch.preparedAt + 1,
          sessionKey: prepared.launch.requestedSessionKey,
          runId: prepared.launch.provisionalRunId,
          execution: {
            id: "late-accepted-execution",
            kind: "agent-session",
            mode: "autonomous",
            status: "running",
            sessionKey: prepared.launch.requestedSessionKey,
            runId: prepared.launch.provisionalRunId,
            startedAt: 10_000,
            updatedAt: 10_001,
          },
        }),
      ).resolves.toBeUndefined();
      await expect(
        store.failPreparedLaunch(card.id, {
          expectedLaunch: prepared.launch,
          reason: "Delayed prepared attempt failure.",
          failedAt: 10_001,
        }),
      ).resolves.toBe(false);
      await expect(store.get(card.id)).resolves.toEqual(before);
    } finally {
      clock.mockRestore();
    }
  });
});
