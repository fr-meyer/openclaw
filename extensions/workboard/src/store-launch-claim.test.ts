import type { WorkboardExecution } from "@openclaw/workboard-contract";
import { describe, expect, it } from "vitest";
import { syncWorkboardSubagentEnded } from "./lifecycle-sync.js";
import { normalizeMetadata } from "./store-normalizers.js";
import type { WorkboardStore } from "./store.js";
import { createWorkboardSqliteTestStore } from "./test/sqlite-store.js";

async function prepareClaimedLaunch(store: WorkboardStore) {
  const card = await store.create({ title: "Launch claim identity", status: "ready" });
  const claimed = await store.claim(card.id, { ownerId: "worker" });
  const prepared = await store.prepareExecutionLaunch(card.id, {
    requestedSessionKey: "agent:worker:subagent:workboard-default-claim-identity",
    now: claimed.card.updatedAt + 1,
    scope: { ownerId: "worker", token: claimed.token },
  });
  return { claimed, prepared };
}

function acceptance(prepared: Awaited<ReturnType<typeof prepareClaimedLaunch>>["prepared"]) {
  const sessionKey = prepared.launch.requestedSessionKey;
  const runId = "accepted-claim-run";
  const execution: WorkboardExecution = {
    id: "claim-execution",
    kind: "agent-session",
    mode: "autonomous",
    status: "running",
    sessionKey,
    runId,
    startedAt: prepared.card.updatedAt,
    updatedAt: prepared.card.updatedAt,
  };
  return {
    expectedLaunch: prepared.launch,
    acceptedAt: prepared.card.updatedAt + 1,
    expectedSessionKey: sessionKey,
    expectedRunId: prepared.launch.provisionalRunId,
    sessionKey,
    runId,
    execution,
  };
}

describe("Workboard launch claim identity", () => {
  it("retains the claim snapshot through acceptance and exact terminal release", async () => {
    const store = createWorkboardSqliteTestStore();
    const { claimed, prepared } = await prepareClaimedLaunch(store);
    const identity = {
      claimOwnerId: "worker",
      claimGeneration: claimed.card.metadata?.claim?.claimedAt,
    };
    expect(prepared.launch).toMatchObject(identity);
    const changed = await store.update(prepared.card.id, {
      metadata: {
        automation: {
          launch: { ...prepared.launch, claimOwnerId: "injected", claimGeneration: 1 },
        },
      },
    });
    expect(changed.metadata?.automation?.launch).toEqual(prepared.launch);
    const accepted = await store.acceptExecutionLaunch(prepared.card.id, acceptance(prepared));
    expect(accepted?.metadata?.automation?.launch).toMatchObject(identity);
    await syncWorkboardSubagentEnded({
      store,
      event: {
        targetSessionKey: prepared.launch.requestedSessionKey,
        runId: "accepted-claim-run",
        endedAt: (accepted?.updatedAt ?? changed.updatedAt) + 1,
        outcome: "ok",
      },
    });
    const terminal = await store.get(prepared.card.id);
    expect(terminal).toMatchObject({ status: "review" });
    expect(terminal?.metadata?.claim).toBeUndefined();
    expect(terminal?.metadata?.automation?.launch).toMatchObject(identity);
    expect(terminal?.metadata?.automation?.launch).not.toHaveProperty("token");
  });

  it("retains a changed owner even when the claim generation timestamp is unchanged", async () => {
    const store = createWorkboardSqliteTestStore();
    const { claimed, prepared } = await prepareClaimedLaunch(store);
    await store.acceptExecutionLaunch(prepared.card.id, acceptance(prepared));
    const changed = await store.update(prepared.card.id, {
      metadata: {
        claim: {
          ...claimed.card.metadata?.claim,
          ownerId: "replacement",
          token: "replacement-token",
        },
      },
    });
    await syncWorkboardSubagentEnded({
      store,
      event: {
        targetSessionKey: prepared.launch.requestedSessionKey,
        runId: "accepted-claim-run",
        endedAt: changed.updatedAt + 1,
        outcome: "ok",
      },
    });
    await expect(store.get(prepared.card.id)).resolves.toMatchObject({
      status: "running",
      metadata: {
        claim: {
          ownerId: "replacement",
          claimedAt: claimed.card.metadata?.claim?.claimedAt,
        },
      },
    });
  });

  it("retains the original claim snapshot after a prepared launch fails", async () => {
    const store = createWorkboardSqliteTestStore();
    const { claimed, prepared } = await prepareClaimedLaunch(store);
    await expect(
      store.failPreparedLaunch(prepared.card.id, {
        expectedLaunch: prepared.launch,
        reason: "Worker could not start.",
        failedAt: prepared.card.updatedAt + 1,
      }),
    ).resolves.toBe(true);
    const failed = await store.get(prepared.card.id);
    expect(failed).toMatchObject({ status: "blocked" });
    expect(failed?.metadata?.claim).toBeUndefined();
    expect(failed?.metadata?.automation?.launch).toMatchObject({
      phase: "failed",
      claimOwnerId: "worker",
      claimGeneration: claimed.card.metadata?.claim?.claimedAt,
    });
  });

  it.each(["owner", "generation"] as const)(
    "rejects prepared launch settlement after the current claim %s changes",
    async (field) => {
      const store = createWorkboardSqliteTestStore();
      const { claimed, prepared } = await prepareClaimedLaunch(store);
      const claim = claimed.card.metadata?.claim;
      if (!claim) {
        throw new Error("expected claimed launch");
      }
      const changed = await store.update(prepared.card.id, {
        metadata: {
          claim: {
            ...claim,
            ...(field === "owner"
              ? { ownerId: "replacement", token: "replacement-token" }
              : { claimedAt: claim.claimedAt + 1 }),
          },
        },
      });
      await expect(
        store.acceptExecutionLaunch(prepared.card.id, acceptance(prepared)),
      ).resolves.toBeUndefined();
      await expect(
        store.failPreparedLaunch(prepared.card.id, {
          expectedLaunch: prepared.launch,
          reason: "Late start failure.",
          failedAt: changed.updatedAt + 1,
        }),
      ).resolves.toBe(false);
      await expect(store.get(prepared.card.id)).resolves.toEqual(changed);
    },
  );

  it("rejects acceptance with a different expected claim generation", async () => {
    const store = createWorkboardSqliteTestStore();
    const { claimed, prepared } = await prepareClaimedLaunch(store);
    const claimGeneration = claimed.card.metadata?.claim?.claimedAt;
    if (claimGeneration === undefined) {
      throw new Error("expected claimed launch");
    }
    await expect(
      store.acceptExecutionLaunch(prepared.card.id, {
        ...acceptance(prepared),
        expectedLaunch: { ...prepared.launch, claimGeneration: claimGeneration + 1 },
      }),
    ).resolves.toBeUndefined();
    expect((await store.get(prepared.card.id))?.metadata?.automation?.launch).toEqual(
      prepared.launch,
    );
  });
});

describe("Workboard launch claim persistence boundary", () => {
  const launch = {
    phase: "accepted",
    requestedSessionKey: "worker-session",
    provisionalRunId: "prepared-run",
    preparedAt: 100,
    acceptedAt: 101,
    acceptedSessionKey: "worker-session",
    acceptedRunId: "accepted-run",
  };

  it("keeps older launch records without inventing a claim identity", () => {
    const metadata = normalizeMetadata(
      { automation: { launch } },
      {},
      { allowAutomationLaunch: true },
    );
    expect(metadata.automation?.launch).toEqual(launch);
  });

  it.each([
    { claimOwnerId: "worker" },
    { claimGeneration: 100 },
    { claimOwnerId: "worker", claimGeneration: 0 },
    { claimOwnerId: "worker", claimGeneration: 1.5 },
    { claimOwnerId: "worker", claimGeneration: Number.MAX_SAFE_INTEGER + 1 },
  ])("rejects an incomplete or invalid persisted claim identity: %j", (identity) => {
    const metadata = normalizeMetadata(
      { automation: { launch: { ...launch, ...identity } } },
      {},
      { allowAutomationLaunch: true },
    );
    expect(metadata.automation?.launch).toBeUndefined();
  });
});
