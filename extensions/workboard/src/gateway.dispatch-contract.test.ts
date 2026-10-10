// Workboard tests cover gateway plugin behavior.
import { createHash } from "node:crypto";
import fs from "node:fs";
import { describe, expect, it, vi } from "vitest";
import type { OpenClawPluginApi } from "../api.js";
import { dispatchAndStartWorkboardCards } from "./dispatcher.js";
import { registerWorkboardGatewayMethods } from "./gateway.js";
import { createWorkboardLiveExecutionTracker } from "./live-execution.js";
import { createWorkboardSqliteTestStore } from "./test/sqlite-store.js";

function createGatewayMethodCapture() {
  type RegisteredMethod = {
    handler: Parameters<OpenClawPluginApi["registerGatewayMethod"]>[1];
    opts: Parameters<OpenClawPluginApi["registerGatewayMethod"]>[2];
  };
  const methods = new Map<string, RegisteredMethod>();
  const api = {
    runtime: {
      state: {
        openKeyedStore: vi.fn(),
      },
    },
    registerGatewayMethod: vi.fn(
      (method: string, handler: RegisteredMethod["handler"], opts: RegisteredMethod["opts"]) => {
        methods.set(method, { handler, opts });
      },
    ),
  } as unknown as OpenClawPluginApi;
  return { api, methods };
}

describe("Workboard dispatch and execution read contracts", () => {
  it("reads exact live settlement without granting release or mutating the card", async () => {
    const store = createWorkboardSqliteTestStore();
    const card = await store.create({
      title: "Bound worker",
      status: "ready",
      workspaceAccess: { unrestricted: true },
    });
    const liveExecutions = createWorkboardLiveExecutionTracker();
    await dispatchAndStartWorkboardCards({
      store,
      liveExecutions,
      subagent: {
        run: async () => ({
          runId: "observed-run",
          execution: { observeSettlement: () => "settled" },
        }),
      },
      options: { cardId: card.id, maxStarts: 1, now: 10 },
    });
    const before = await store.get(card.id);
    const { api, methods } = createGatewayMethodCapture();
    registerWorkboardGatewayMethods({ api, store, liveExecutions });
    const method = methods.get("workboard.cards.executionSettlement")!;
    expect(method.opts).toEqual({ scope: "operator.read" });
    const respond = vi.fn();
    await method.handler({ params: { id: card.id }, respond } as never);
    expect(respond).toHaveBeenCalledWith(
      true,
      expect.objectContaining({
        cardId: card.id,
        runId: "observed-run",
        producerState: "settled",
        resourceFencing: "unknown",
        releaseAuthorized: false,
      }),
    );
    expect(await store.get(card.id)).toEqual(before);
    const claim = before?.metadata?.claim;
    expect(claim).toBeDefined();
    const released = await store.releaseClaim(card.id, {
      ownerId: claim!.ownerId,
      token: claim!.token,
      status: "review",
    });
    expect(released.metadata?.claim).toBeUndefined();
    expect(released.metadata?.automation?.launch).toEqual(before?.metadata?.automation?.launch);
    respond.mockClear();
    await method.handler({ params: { id: card.id }, respond } as never);
    expect(respond).toHaveBeenCalledWith(
      true,
      expect.objectContaining({
        runId: "observed-run",
        claimOwnerId: claim!.ownerId,
        claimGeneration: claim!.claimedAt,
        producerState: "settled",
        resourceFencing: "unknown",
        releaseAuthorized: false,
      }),
    );
    expect(await store.get(card.id)).toEqual(released);
    liveExecutions.stop();
    respond.mockClear();
    await method.handler({ params: { id: card.id }, respond } as never);
    expect(respond).toHaveBeenCalledWith(
      true,
      expect.objectContaining({ producerState: "unknown" }),
    );
  });

  it("exposes exact-card targeting through the existing dashboard dispatch action", () => {
    const manifest = JSON.parse(
      fs.readFileSync(new URL("../openclaw.plugin.json", import.meta.url), "utf8"),
    ) as {
      dashboard?: {
        actionVerbs?: Array<{
          id?: string;
          method?: string;
          paramShape?: { properties?: Record<string, unknown> };
        }>;
      };
    };
    const dispatch = manifest.dashboard?.actionVerbs?.find((entry) => entry.id === "dispatch");

    expect(dispatch).toMatchObject({
      method: "workboard.cards.dispatchWithTarget",
      paramShape: {
        properties: {
          boardId: expect.any(Object),
          cardId: expect.objectContaining({ type: "string", minLength: 1 }),
          maxStarts: expect.objectContaining({ type: "integer", minimum: 1 }),
        },
      },
    });
  });

  it("dispatches one exact RPC card without enumerating or mutating unrelated cards", async () => {
    vi.useFakeTimers();
    try {
      vi.setSystemTime(1_000_000);
      type RegisteredMethod = {
        handler: Parameters<OpenClawPluginApi["registerGatewayMethod"]>[1];
        opts: Parameters<OpenClawPluginApi["registerGatewayMethod"]>[2];
      };
      const methods = new Map<string, RegisteredMethod>();
      const run = vi.fn().mockResolvedValue({ runId: "run-target" });
      const api = {
        runtime: {
          state: { openKeyedStore: vi.fn() },
          subagent: { run },
        },
        registerGatewayMethod: vi.fn(
          (
            method: string,
            handler: RegisteredMethod["handler"],
            opts: RegisteredMethod["opts"],
          ) => {
            methods.set(method, { handler, opts });
          },
        ),
      } as unknown as OpenClawPluginApi;
      const store = createWorkboardSqliteTestStore();
      const stale = await store.create({
        title: "Unrelated expired worker",
        status: "ready",
        boardId: "ops",
        agentId: "expired-owner",
      });
      await store.claim(stale.id, {
        ownerId: "expired-owner",
        token: "expired-token",
        ttlSeconds: 1,
      });
      const sibling = await store.create({
        title: "Unrelated urgent card",
        status: "ready",
        priority: "urgent",
        boardId: "ops",
        agentId: "urgent-owner",
        workspaceAccess: { unrestricted: true },
      });
      const target = await store.create({
        title: "Exact RPC target",
        status: "ready",
        priority: "low",
        boardId: "ops",
        agentId: "target-owner",
        workspaceAccess: { unrestricted: true },
      });
      vi.setSystemTime(1_000_000 + 10 * 60 * 1000);
      const staleBefore = await store.get(stale.id);
      const siblingBefore = await store.get(sibling.id);
      const list = vi.spyOn(store, "list");
      registerWorkboardGatewayMethods({ api, store });
      const respond = vi.fn();
      const intentRunId = `wb-${"a".repeat(40)}`;

      await methods.get("workboard.cards.dispatchWithTarget")?.handler({
        params: { boardId: "ops", cardId: target.id, intentRunId },
        context: { getRuntimeConfig: () => ({}) },
        respond,
      } as never);

      expect(list).not.toHaveBeenCalled();
      expect(run).toHaveBeenCalledOnce();
      const expectedKey = `workboard:intent:${createHash("sha256")
        .update(target.id)
        .update("\0")
        .update(intentRunId)
        .digest("hex")}`;
      expect(run.mock.calls[0]?.[0]).toMatchObject({ idempotencyKey: expectedKey });
      expect(respond.mock.calls[0]?.[0]).toBe(true);
      expect(respond.mock.calls[0]?.[1]).toMatchObject({
        started: [expect.objectContaining({ cardId: target.id, runId: "run-target" })],
      });
      expect(respond.mock.calls[0]?.[1]?.started[0]).not.toHaveProperty("card");
      await expect(store.get(target.id)).resolves.toMatchObject({
        status: "running",
        metadata: {
          automation: {
            dispatchCount: 1,
            lastDispatchAt: Date.now(),
            launch: { provisionalRunId: expectedKey, acceptedRunId: "run-target" },
          },
          claim: { ownerId: "target-owner" },
        },
      });
      await expect(store.get(stale.id)).resolves.toEqual(staleBefore);
      await expect(store.get(sibling.id)).resolves.toEqual(siblingBefore);
    } finally {
      vi.useRealTimers();
    }
  });
});
