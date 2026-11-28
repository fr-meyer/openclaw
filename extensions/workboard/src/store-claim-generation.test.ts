import type { WorkboardClaim, WorkboardLaunchState } from "@openclaw/workboard-contract";
import { describe, expect, it, vi } from "vitest";
import { syncWorkboardSubagentEnded } from "./lifecycle-sync.js";
import { createKernelStores } from "./test/sqlite-kernel.js";
import { createWorkboardSqliteTestHarness } from "./test/sqlite-store.js";

const identity = {
  requestedSessionKey: "subagent:workboard-default-generation",
  provisionalRunId: "workboard:intent:stable",
  preparedAt: 10_000,
};

describe("persisted Workboard claim generations", () => {
  it.each<WorkboardLaunchState>([
    { ...identity, phase: "prepared" },
    {
      ...identity,
      phase: "accepted",
      acceptedAt: 10_001,
      acceptedSessionKey: "accepted-session",
      acceptedRunId: "accepted-run",
    },
    { ...identity, phase: "failed", failedAt: 10_001, reason: "Launch failed" },
  ])("preserves $phase claim snapshots through SQLite and a normalized update", async (launch) => {
    const { store, stores } = createWorkboardSqliteTestHarness({
      createStores: createKernelStores,
    });
    const card = await store.create({ title: "Existing persisted launch" });
    const expected = { ...launch, claimOwnerId: "worker", claimGeneration: 9_999 };
    await stores.cards.register(card.id, {
      version: 1,
      card: { ...card, metadata: { automation: { launch: expected } } },
    });

    await store.update(card.id, {
      metadata: { automation: { summary: "Normalize existing launch metadata" } },
    });

    expect((await stores.cards.lookup(card.id))?.card.metadata?.automation?.launch).toEqual(
      expected,
    );
  });

  it.each([
    { claimOwnerId: "worker" },
    { claimGeneration: 1 },
    { claimOwnerId: "worker", claimGeneration: 0 },
    { claimOwnerId: "worker", claimGeneration: 1.5 },
    { claimOwnerId: "worker", claimGeneration: Number.MAX_SAFE_INTEGER + 1 },
  ])("does not retain malformed imported claim snapshots %#", async (snapshot) => {
    const { store, stores } = createWorkboardSqliteTestHarness({
      createStores: createKernelStores,
    });
    const card = await store.create({ title: "Malformed imported launch" });
    await stores.cards.register(card.id, {
      version: 1,
      card: {
        ...card,
        metadata: {
          automation: {
            launch: { ...identity, phase: "prepared", ...snapshot },
          },
        },
      },
    });

    await store.update(card.id, {
      metadata: { automation: { summary: "Normalize the persisted record" } },
    });

    expect((await stores.cards.lookup(card.id))?.card.metadata?.automation?.launch).toBeUndefined();
  });

  it.each([
    { completion: "accept", replacement: false },
    { completion: "accept", replacement: true },
    { completion: "fail", replacement: false },
    { completion: "fail", replacement: true },
  ])(
    "guards legacy prepared $completion against a replacement claim (replacement=$replacement)",
    async ({ completion, replacement }) => {
      const clock = vi.spyOn(Date, "now").mockReturnValue(10_000);
      try {
        const { store, stores } = createWorkboardSqliteTestHarness({
          createStores: createKernelStores,
        });
        const card = await store.create({ title: "Legacy prepared launch", status: "ready" });
        const claimed = await store.claim(card.id, { ownerId: "worker", token: "first-token" });
        const prepared = await store.prepareExecutionLaunch(card.id, {
          requestedSessionKey: identity.requestedSessionKey,
          now: 10_000,
          scope: { ownerId: "worker", token: claimed.token },
          intentRunId: `wb-${"a".repeat(40)}`,
        });
        const launch = { ...prepared.launch };
        delete launch.claimOwnerId;
        delete launch.claimGeneration;
        await stores.cards.register(card.id, {
          version: 1,
          card: {
            ...prepared.card,
            metadata: {
              ...prepared.card.metadata,
              automation: { ...prepared.card.metadata?.automation, launch },
            },
          },
        });
        if (replacement) {
          await store.releaseClaim(card.id, { ownerId: "worker", token: claimed.token });
          const replaced = await store.claim(card.id, {
            ownerId: "worker",
            token: "replacement-token",
          });
          expect(replaced.card.metadata?.claim?.ownerId).toBe("worker");
          expect(replaced.card.metadata?.claim?.claimedAt).toBeGreaterThan(launch.preparedAt);
          expect(Date.now()).toBe(10_000);
        }
        const before = await store.get(card.id);
        expect(before?.metadata?.automation?.launch).toEqual(launch);

        if (completion === "accept") {
          const acceptedAt = launch.preparedAt + 1;
          const accepted = await store.acceptExecutionLaunch(card.id, {
            expectedLaunch: launch,
            expectedSessionKey: launch.requestedSessionKey,
            expectedRunId: launch.provisionalRunId,
            acceptedAt,
            sessionKey: launch.requestedSessionKey,
            runId: launch.provisionalRunId,
            execution: {
              id: "legacy-accepted-execution",
              kind: "agent-session",
              mode: "autonomous",
              status: "running",
              sessionKey: launch.requestedSessionKey,
              runId: launch.provisionalRunId,
              startedAt: 10_000,
              updatedAt: acceptedAt,
            },
          });
          if (replacement) {
            expect(accepted).toBeUndefined();
          } else {
            expect(accepted?.metadata?.automation?.launch?.phase).toBe("accepted");
          }
        } else {
          await expect(
            store.failPreparedLaunch(card.id, {
              expectedLaunch: launch,
              reason: "Delayed legacy prepared failure.",
              failedAt: launch.preparedAt + 1,
            }),
          ).resolves.toBe(!replacement);
        }
        if (replacement) {
          await expect(store.get(card.id)).resolves.toEqual(before);
        }
      } finally {
        clock.mockRestore();
      }
    },
  );

  it.each([
    { legacy: false, replacement: false },
    { legacy: false, replacement: true },
    { legacy: true, replacement: false },
    { legacy: true, replacement: true },
  ])(
    "settles only the accepted claim generation (legacy=$legacy, replacement=$replacement)",
    async ({ legacy, replacement }) => {
      const clock = vi.spyOn(Date, "now").mockReturnValue(10_000);
      try {
        const { store, stores } = createWorkboardSqliteTestHarness({
          createStores: createKernelStores,
        });
        const card = await store.create({ title: "Stable accepted run", status: "ready" });
        const claimed = await store.claim(card.id, { ownerId: "worker", token: "first-token" });
        const prepared = await store.prepareExecutionLaunch(card.id, {
          requestedSessionKey: identity.requestedSessionKey,
          now: 10_000,
          scope: { ownerId: "worker", token: claimed.token },
          intentRunId: `wb-${"a".repeat(40)}`,
        });
        const sessionKey = `agent:worker:${identity.requestedSessionKey}`;
        const acceptedAt = prepared.launch.preparedAt + 1;
        const accepted = await store.acceptExecutionLaunch(card.id, {
          expectedLaunch: prepared.launch,
          expectedSessionKey: prepared.launch.requestedSessionKey,
          expectedRunId: prepared.launch.provisionalRunId,
          acceptedAt,
          sessionKey,
          runId: "same-accepted-run",
          execution: {
            id: "accepted-execution",
            kind: "agent-session",
            mode: "autonomous",
            status: "running",
            sessionKey,
            runId: "same-accepted-run",
            startedAt: 10_000,
            updatedAt: acceptedAt,
          },
        });
        expect(accepted).toBeDefined();
        if (!accepted?.metadata?.automation?.launch) {
          throw new Error("Expected accepted launch");
        }
        if (legacy) {
          const launch = { ...accepted.metadata.automation.launch };
          delete launch.claimOwnerId;
          delete launch.claimGeneration;
          await stores.cards.register(card.id, {
            version: 1,
            card: {
              ...accepted,
              metadata: {
                ...accepted.metadata,
                automation: { ...accepted.metadata.automation, launch },
              },
            },
          });
        }
        let replacementClaim: WorkboardClaim | undefined;
        if (replacement) {
          await store.releaseClaim(card.id, { ownerId: "worker", token: claimed.token });
          replacementClaim = (
            await store.claim(card.id, { ownerId: "worker", token: "replacement-token" })
          ).card.metadata?.claim;
          expect(replacementClaim?.claimedAt).toBeGreaterThan(prepared.launch.preparedAt);
        }

        const count = await syncWorkboardSubagentEnded({
          store,
          event: {
            targetSessionKey: sessionKey,
            runId: "same-accepted-run",
            endedAt: acceptedAt + 100,
            outcome: "ok",
          },
          now: acceptedAt + 100,
        });
        const current = await store.get(card.id);

        expect(count).toBe(replacement ? 0 : 1);
        expect(current?.status).toBe(replacement ? "running" : "review");
        expect(current?.metadata?.claim).toEqual(replacement ? replacementClaim : undefined);
        expect(current?.runId).toBe("same-accepted-run");
      } finally {
        clock.mockRestore();
      }
    },
  );
});
