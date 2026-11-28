// Workboard tests cover gateway plugin behavior.
import { createHash } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import type { OpenClawPluginApi } from "../api.js";
import { registerWorkboardGatewayMethods } from "./gateway.js";
import { createGatewayMethodCapture } from "./test/gateway-methods.js";
import { createWorkboardSqliteTestStore } from "./test/sqlite-store.js";

describe("workboard gateway methods", () => {
  it("validates exact-card dispatch options before touching worker state", async () => {
    const { api, methods, invoke } = createGatewayMethodCapture();
    const store = createWorkboardSqliteTestStore();
    using dispatch = vi.spyOn(store, "dispatch");
    using prepareStart = vi.spyOn(store, "prepareStart");
    registerWorkboardGatewayMethods({ api, store });
    expect(methods.get("workboard.cards.dispatchWithOptions")?.opts).toEqual({
      scope: "operator.write",
    });
    const intent = `wb-${"a".repeat(40)}`;
    const cases: Array<[string, Record<string, unknown>, string]> = [
      ["dispatch", { cardId: "target" }, "cardId requires workboard.cards.dispatchWithOptions."],
      [
        "dispatch",
        { intentRunId: intent },
        "intentRunId requires one exact card through dispatchWithOptions.",
      ],
      ...[null, 42, "   "].map((cardId): [string, Record<string, unknown>, string] => [
        "dispatchWithOptions",
        { cardId },
        "cardId must be a non-empty string.",
      ]),
      [
        "dispatchWithOptions",
        { cardId: "target", maxStarts: 2 },
        "maxStarts must be 1 when cardId is provided.",
      ],
      [
        "dispatchWithOptions",
        { intentRunId: intent },
        "intentRunId requires one exact card through dispatchWithOptions.",
      ],
      ...["bad", `wb-${"A".repeat(40)}`, `wb-${"a".repeat(39)}`, `${intent}\n`].map(
        (intentRunId): [string, Record<string, unknown>, string] => [
          "dispatchWithOptions",
          { cardId: "target", intentRunId },
          "intentRunId must be a wb-<40 lowercase hex> dispatch intent id.",
        ],
      ),
      [
        "start",
        { id: "target", intentRunId: intent },
        "intentRunId requires one exact card through dispatchWithOptions.",
      ],
    ];
    for (const [method, input, message] of cases) {
      const respond = await invoke(`workboard.cards.${method}`, input);
      expect(respond).toHaveBeenCalledWith(false, undefined, {
        code: "workboard_error",
        message,
      });
    }
    expect(dispatch).not.toHaveBeenCalled();
    expect(prepareStart).not.toHaveBeenCalled();
  });

  it("dispatches only the exact card, forwards its intent, and omits private card state", async () => {
    const { api, methods } = createGatewayMethodCapture();
    const run = vi.fn(async (input: { idempotencyKey: string }) => ({
      runId: `accepted:${input.idempotencyKey}`,
    }));
    api.runtime.subagent = { run } as unknown as OpenClawPluginApi["runtime"]["subagent"];
    const store = createWorkboardSqliteTestStore();
    const target = await store.create({
      title: "Exact dispatch",
      status: "ready",
      agentId: "target",
      workspaceAccess: { unrestricted: true },
    });
    const unrelated = await store.create({
      title: "Unrelated urgent work",
      status: "ready",
      priority: "urgent",
      agentId: "other",
      workspaceAccess: { unrestricted: true },
    });
    using list = vi.spyOn(store, "list");
    using prepareStart = vi.spyOn(store, "prepareStart");
    using prepareLaunch = vi.spyOn(store, "prepareExecutionLaunch");
    registerWorkboardGatewayMethods({ api, store });
    const intentRunId = `wb-${"b".repeat(40)}`;
    const respond = vi.fn();
    await methods.get("workboard.cards.dispatchWithOptions")!.handler({
      params: { cardId: target.id, intentRunId },
      context: { getRuntimeConfig: () => ({}) },
      respond,
    } as never);
    expect(respond.mock.calls[0]?.[0]).toBe(true);
    expect(respond.mock.calls[0]?.[1]).toMatchObject({
      started: [{ cardId: target.id }],
      startFailures: [],
    });
    expect(respond.mock.calls[0]?.[1].started[0]).not.toHaveProperty("card");
    expect(prepareLaunch).toHaveBeenCalledWith(target.id, expect.objectContaining({ intentRunId }));
    expect(prepareStart).not.toHaveBeenCalled();
    expect(list).not.toHaveBeenCalled();
    expect(run).toHaveBeenCalledOnce();
    await expect(store.get(unrelated.id)).resolves.toEqual(unrelated);
  });

  it("keeps exact dispatch eligibility and response separate from direct start", async () => {
    const { api, methods } = createGatewayMethodCapture();
    const run = vi.fn().mockResolvedValue({ runId: "run-manual-card" });
    api.runtime.subagent = { run } as unknown as OpenClawPluginApi["runtime"]["subagent"];
    const store = createWorkboardSqliteTestStore();
    const target = await store.create({
      title: "Manual todo card",
      status: "todo",
      workspaceAccess: { unrestricted: true },
    });
    const unrelated = await store.create({
      title: "Unrelated ready card",
      status: "ready",
      agentId: "other",
      workspaceAccess: { unrestricted: true },
    });
    registerWorkboardGatewayMethods({ api, store });
    const respond = vi.fn();
    await methods.get("workboard.cards.dispatchWithOptions")!.handler({
      params: { cardId: target.id, maxStarts: 1 },
      context: { getRuntimeConfig: () => ({}) },
      respond,
    } as never);
    expect(respond.mock.calls[0]?.[0]).toBe(true);
    expect(respond.mock.calls[0]?.[1]).toMatchObject({
      started: [],
      startFailures: [{ cardId: target.id, error: expect.stringContaining("cannot dispatch") }],
    });
    expect(run).not.toHaveBeenCalled();
    await expect(store.get(unrelated.id)).resolves.toEqual(unrelated);
    const direct = vi.fn();
    await methods.get("workboard.cards.start")!.handler({
      params: { id: target.id, provider: "openai", model: "test-model" },
      context: { getRuntimeConfig: () => ({}) },
      respond: direct,
    } as never);
    expect(direct.mock.calls[0]?.[0]).toBe(true);
    expect(direct.mock.calls[0]?.[1]).toMatchObject({
      cardId: target.id,
      runId: "run-manual-card",
    });
    expect(direct.mock.calls[0]?.[1]).not.toHaveProperty("started");
    expect(run).toHaveBeenCalledOnce();
    expect(run).toHaveBeenCalledWith(
      expect.objectContaining({ provider: "openai", model: "test-model" }),
    );
  });

  it("keeps connected exact-card dispatch within configured workspace authority", async () => {
    const { api, methods } = createGatewayMethodCapture();
    const run = vi.fn();
    api.runtime.subagent = { run } as unknown as OpenClawPluginApi["runtime"]["subagent"];
    const store = createWorkboardSqliteTestStore();
    const target = await store.create({
      title: "Outside exact target",
      status: "ready",
      workspace: { kind: "worktree", sourcePath: "/outside/workboard-repo" },
      workspaceAccess: { unrestricted: true },
    });
    registerWorkboardGatewayMethods({ api, store });
    const respond = vi.fn();
    await methods.get("workboard.cards.dispatchWithOptions")!.handler({
      params: { cardId: target.id },
      client: { connect: { scopes: ["operator.write"] } },
      context: {
        getRuntimeConfig: () => ({ agents: { defaults: { workspace: "/workspace" } } }),
      },
      respond,
    } as never);
    expect(respond.mock.calls[0]?.[0]).toBe(true);
    expect(respond.mock.calls[0]?.[1]).toMatchObject({
      started: [],
      startFailures: [{ cardId: target.id, error: expect.stringContaining("outside the caller") }],
    });
    expect(run).not.toHaveBeenCalled();
    await expect(store.get(target.id)).resolves.toMatchObject({ status: "ready" });
  });

  it("returns an actionable exact-card admission failure", async () => {
    const { methods, registerGatewayMethod } = createGatewayMethodCapture();
    const run = vi.fn();
    const api = {
      runtime: {
        state: { openKeyedStore: vi.fn() },
        subagent: { run },
      },
      registerGatewayMethod,
    } as unknown as OpenClawPluginApi;
    const store = createWorkboardSqliteTestStore();
    const card = await store.create({
      title: "Blocked exact start",
      status: "blocked",
      workspaceAccess: { unrestricted: true },
    });
    registerWorkboardGatewayMethods({ api, store });
    const respond = vi.fn();

    await methods.get("workboard.cards.start")?.handler({
      params: { id: card.id },
      context: { getRuntimeConfig: () => ({}) },
      respond,
    } as never);

    expect(run).not.toHaveBeenCalled();
    expect(respond).toHaveBeenCalledWith(
      false,
      undefined,
      expect.objectContaining({
        code: "workboard_error",
        message: expect.stringMatching(/blocked.*backlog.*todo.*ready/i),
      }),
    );
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

      await methods.get("workboard.cards.dispatchWithOptions")?.handler({
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

  it("threads maxStarts while the legacy method keeps its default cap", async () => {
    const { methods, registerGatewayMethod } = createGatewayMethodCapture();
    const run = vi.fn(async (input: { idempotencyKey: string }) => ({
      runId: `accepted:${input.idempotencyKey}`,
    }));
    const api = {
      runtime: {
        state: { openKeyedStore: vi.fn() },
        subagent: { run },
      },
      registerGatewayMethod,
    } as unknown as OpenClawPluginApi;
    const store = createWorkboardSqliteTestStore();
    await Promise.all(
      Array.from({ length: 5 }, (_, index) =>
        store.create({
          title: `Capped ${index}`,
          status: "ready",
          priority: "urgent",
          agentId: `capped-${index}`,
          boardId: "capped",
          workspaceAccess: { unrestricted: true },
        }),
      ),
    );
    registerWorkboardGatewayMethods({ api, store });
    const handler = methods.get("workboard.cards.dispatchWithOptions")?.handler;

    const respond = vi.fn();
    await handler?.({ params: { boardId: "capped", maxStarts: 4 }, respond } as never);

    expect(respond.mock.calls[0]?.[0]).toBe(true);
    expect(respond.mock.calls[0]?.[1]?.started).toHaveLength(4);
    expect(run).toHaveBeenCalledTimes(4);

    const defaultCards = await Promise.all(
      Array.from({ length: 5 }, (_, index) =>
        store.create({
          title: `Legacy ${index}`,
          status: "ready",
          priority: "urgent",
          agentId: index === 0 ? undefined : `legacy-${index}`,
          boardId: "default",
          workspaceAccess: { unrestricted: true },
        }),
      ),
    );
    const defaultRespond = vi.fn();
    await methods.get("workboard.cards.dispatch")?.handler({ respond: defaultRespond } as never);
    expect(defaultRespond.mock.calls[0]?.[0]).toBe(true);
    expect(defaultRespond.mock.calls[0]?.[1]?.started).toHaveLength(3);
    await expect(store.get(defaultCards[0]!.id)).resolves.toMatchObject({ status: "running" });
    expect(run).toHaveBeenCalledTimes(7);
    const startedCards = (await store.list()).filter((card) => card.status === "running");
    expect(startedCards).toHaveLength(7);
    const expectedRunIds = run.mock.calls.map(([input]) => `accepted:${input.idempotencyKey}`);
    expect(startedCards.map((card) => card.runId)).toEqual(expect.arrayContaining(expectedRunIds));
    for (const card of startedCards) {
      const runId = card.runId;
      if (defaultCards.some(({ id }) => id === card.id)) {
        expect(defaultRespond.mock.calls[0]?.[1]).toMatchObject({
          started: expect.arrayContaining([expect.objectContaining({ cardId: card.id, runId })]),
        });
        expect(run).toHaveBeenCalledWith(
          expect.objectContaining({
            sessionKey: `${card.agentId ? `agent:${card.agentId}:` : ""}subagent:workboard-default-${card.id}`,
          }),
        );
      }
      expect(card).toMatchObject({
        runId,
        execution: { runId },
        metadata: {
          automation: { launch: { phase: "accepted", acceptedRunId: runId } },
          attempts: [expect.objectContaining({ id: runId, runId })],
        },
      });
    }

    const legacyRespond = vi.fn();
    await methods
      .get("workboard.cards.dispatch")
      ?.handler({ params: { maxStarts: 1 }, respond: legacyRespond } as never);
    expect(legacyRespond.mock.calls[0]?.[0]).toBe(false);
    expect(legacyRespond.mock.calls[0]?.[2]?.message).toBe(
      "maxStarts requires workboard.cards.dispatchWithOptions.",
    );

    const legacyCardRespond = vi.fn();
    await methods
      .get("workboard.cards.dispatch")
      ?.handler({ params: { cardId: "card-1" }, respond: legacyCardRespond } as never);
    expect(legacyCardRespond.mock.calls[0]?.[0]).toBe(false);
    expect(legacyCardRespond.mock.calls[0]?.[2]?.message).toBe(
      "cardId requires workboard.cards.dispatchWithOptions.",
    );

    for (const value of ["", "   ", 42]) {
      const invalidCardRespond = vi.fn();
      await handler?.({ params: { cardId: value }, respond: invalidCardRespond } as never);
      expect(invalidCardRespond.mock.calls[0]?.[0]).toBe(false);
      expect(invalidCardRespond.mock.calls[0]?.[2]?.message).toBe(
        "cardId must be a non-empty string.",
      );
    }

    for (const value of ["", "   ", 42, null, undefined]) {
      const invalidBoardRespond = vi.fn();
      await handler?.({ params: { boardId: value }, respond: invalidBoardRespond } as never);
      expect(invalidBoardRespond.mock.calls[0]?.[0]).toBe(false);
      expect(invalidBoardRespond.mock.calls[0]?.[2]?.message).toBe(
        "boardId must be a non-empty string.",
      );
    }

    const unscopedIntent = vi.fn();
    await handler?.({
      params: { intentRunId: `wb-${"b".repeat(40)}` },
      respond: unscopedIntent,
    } as never);
    expect(unscopedIntent.mock.calls[0]?.[2]?.message).toBe(
      "intentRunId requires one exact card through dispatchWithOptions.",
    );
    for (const value of ["bad", 42, `wb-${"A".repeat(40)}`]) {
      const invalidIntent = vi.fn();
      await handler?.({
        params: { cardId: "card-1", intentRunId: value },
        respond: invalidIntent,
      } as never);
      expect(invalidIntent.mock.calls[0]?.[2]?.message).toBe(
        "intentRunId must be a wb-<40 lowercase hex> dispatch intent id.",
      );
    }
    expect(run).toHaveBeenCalledTimes(7);

    const exactCapRespond = vi.fn();
    await handler?.({
      params: { cardId: "card-1", maxStarts: 2 },
      respond: exactCapRespond,
    } as never);
    expect(exactCapRespond.mock.calls[0]?.[0]).toBe(false);
    expect(exactCapRespond.mock.calls[0]?.[2]?.message).toBe(
      "maxStarts must be 1 when cardId is provided.",
    );

    for (const value of [0, -1, 1.5, "2"]) {
      const invalidRespond = vi.fn();
      await handler?.({ params: { maxStarts: value }, respond: invalidRespond } as never);
      expect(invalidRespond.mock.calls[0]?.[0]).toBe(false);
      expect(invalidRespond.mock.calls[0]?.[2]?.message).toBe(
        "maxStarts must be a positive integer.",
      );
    }
  });

  it("threads maxStarts and dispatches omitted params with the legacy default cap", async () => {
    const { methods, registerGatewayMethod } = createGatewayMethodCapture();
    const run = vi.fn(async (input: { idempotencyKey: string }) => ({
      runId: `accepted:${input.idempotencyKey}`,
    }));
    const api = {
      runtime: {
        state: { openKeyedStore: vi.fn() },
        subagent: { run },
      },
      registerGatewayMethod,
    } as unknown as OpenClawPluginApi;
    const store = createWorkboardSqliteTestStore();
    await Promise.all(
      Array.from({ length: 5 }, (_, index) =>
        store.create({
          title: `Capped ${index}`,
          status: "ready",
          priority: "urgent",
          agentId: `capped-${index}`,
          boardId: "capped",
          workspaceAccess: { unrestricted: true },
        }),
      ),
    );
    registerWorkboardGatewayMethods({ api, store });
    const handler = methods.get("workboard.cards.dispatchWithOptions")?.handler;

    const respond = vi.fn();
    await handler?.({ params: { boardId: "capped", maxStarts: 4 }, respond } as never);

    expect(respond.mock.calls[0]?.[0]).toBe(true);
    expect(respond.mock.calls[0]?.[1]?.started).toHaveLength(4);
    expect(run).toHaveBeenCalledTimes(4);

    const defaultCards = await Promise.all(
      Array.from({ length: 5 }, (_, index) =>
        store.create({
          title: `Legacy ${index}`,
          status: "ready",
          priority: "urgent",
          agentId: index === 0 ? undefined : `legacy-${index}`,
          boardId: "default",
          workspaceAccess: { unrestricted: true },
        }),
      ),
    );
    const defaultRespond = vi.fn();
    await methods.get("workboard.cards.dispatch")?.handler({ respond: defaultRespond } as never);
    expect(defaultRespond.mock.calls[0]?.[0]).toBe(true);
    expect(defaultRespond.mock.calls[0]?.[1]?.started).toHaveLength(3);
    await expect(store.get(defaultCards[0]!.id)).resolves.toMatchObject({ status: "running" });
    expect(run).toHaveBeenCalledTimes(7);
    const startedCards = (await store.list()).filter((card) => card.status === "running");
    expect(startedCards).toHaveLength(7);
    const expectedRunIds = run.mock.calls.map(([input]) => `accepted:${input.idempotencyKey}`);
    expect(startedCards.map((card) => card.runId)).toEqual(expect.arrayContaining(expectedRunIds));
    for (const card of startedCards) {
      const runId = card.runId;
      if (defaultCards.some(({ id }) => id === card.id)) {
        expect(defaultRespond.mock.calls[0]?.[1]).toMatchObject({
          started: expect.arrayContaining([expect.objectContaining({ cardId: card.id, runId })]),
        });
        expect(run).toHaveBeenCalledWith(
          expect.objectContaining({
            sessionKey: `${card.agentId ? `agent:${card.agentId}:` : ""}subagent:workboard-default-${card.id}`,
          }),
        );
      }
      expect(card).toMatchObject({
        runId,
        execution: { runId },
        metadata: {
          automation: { launch: { phase: "accepted", acceptedRunId: runId } },
          attempts: [expect.objectContaining({ id: runId, runId })],
        },
      });
    }

    const legacyRespond = vi.fn();
    await methods
      .get("workboard.cards.dispatch")
      ?.handler({ params: { maxStarts: 1 }, respond: legacyRespond } as never);
    expect(legacyRespond.mock.calls[0]?.[0]).toBe(false);
    expect(legacyRespond.mock.calls[0]?.[2]?.message).toBe(
      "maxStarts requires workboard.cards.dispatchWithOptions.",
    );

    const legacyCardRespond = vi.fn();
    await methods
      .get("workboard.cards.dispatch")
      ?.handler({ params: { cardId: "card-1" }, respond: legacyCardRespond } as never);
    expect(legacyCardRespond.mock.calls[0]?.[0]).toBe(false);
    expect(legacyCardRespond.mock.calls[0]?.[2]?.message).toBe(
      "cardId requires workboard.cards.dispatchWithOptions.",
    );

    for (const value of ["", "   ", 42]) {
      const invalidCardRespond = vi.fn();
      await handler?.({ params: { cardId: value }, respond: invalidCardRespond } as never);
      expect(invalidCardRespond.mock.calls[0]?.[0]).toBe(false);
      expect(invalidCardRespond.mock.calls[0]?.[2]?.message).toBe(
        "cardId must be a non-empty string.",
      );
    }

    for (const value of ["", "   ", 42]) {
      const invalidBoardRespond = vi.fn();
      await handler?.({ params: { boardId: value }, respond: invalidBoardRespond } as never);
      expect(invalidBoardRespond.mock.calls[0]?.[0]).toBe(false);
      expect(invalidBoardRespond.mock.calls[0]?.[2]?.message).toBe(
        "boardId must be a non-empty string.",
      );
    }

    const unscopedIntent = vi.fn();
    await handler?.({
      params: { intentRunId: `wb-${"b".repeat(40)}` },
      respond: unscopedIntent,
    } as never);
    expect(unscopedIntent.mock.calls[0]?.[2]?.message).toBe(
      "intentRunId requires one exact card through dispatchWithOptions.",
    );
    for (const value of ["bad", 42, `wb-${"A".repeat(40)}`]) {
      const invalidIntent = vi.fn();
      await handler?.({
        params: { cardId: "card-1", intentRunId: value },
        respond: invalidIntent,
      } as never);
      expect(invalidIntent.mock.calls[0]?.[2]?.message).toBe(
        "intentRunId must be a wb-<40 lowercase hex> dispatch intent id.",
      );
    }
    expect(run).toHaveBeenCalledTimes(7);

    const exactCapRespond = vi.fn();
    await handler?.({
      params: { cardId: "card-1", maxStarts: 2 },
      respond: exactCapRespond,
    } as never);
    expect(exactCapRespond.mock.calls[0]?.[0]).toBe(false);
    expect(exactCapRespond.mock.calls[0]?.[2]?.message).toBe(
      "maxStarts must be 1 when cardId is provided.",
    );

    for (const value of [0, -1, 1.5, "2"]) {
      const invalidRespond = vi.fn();
      await handler?.({ params: { maxStarts: value }, respond: invalidRespond } as never);
      expect(invalidRespond.mock.calls[0]?.[0]).toBe(false);
      expect(invalidRespond.mock.calls[0]?.[2]?.message).toBe(
        "maxStarts must be a positive integer.",
      );
    }
  });
});
