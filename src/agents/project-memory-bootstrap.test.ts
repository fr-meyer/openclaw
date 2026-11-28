import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { MemorySearchResult } from "../memory-host-sdk/host/types.js";
import type { MemorySearchHit } from "../plugins/memory-provider-types.js";
import {
  buildProjectMemoryWriteInstruction,
  filterProjectScopedCuratedContextFiles,
  prepareProjectMemoryBootstrap,
} from "./project-memory-bootstrap.js";

const runtimeMocks = vi.hoisted(() => ({
  getManager: vi.fn(),
  getProvider: vi.fn(),
  listCurated: vi.fn(),
  search: vi.fn(),
  legacyRuntime: undefined as unknown,
  providerRuntime: undefined as unknown,
}));

const logMocks = vi.hoisted(() => ({ debug: vi.fn() }));

vi.mock("../plugins/memory-state.js", () => ({
  getMemoryRuntime: () => runtimeMocks.legacyRuntime,
  resolveLoadedMemoryProviderKind: () =>
    runtimeMocks.providerRuntime ? "native" : runtimeMocks.legacyRuntime ? "legacy" : undefined,
}));
vi.mock("../plugins/memory-runtime.js", () => ({
  getActiveMemoryProviderCore: (...args: unknown[]) => runtimeMocks.getProvider(...args),
}));
vi.mock("../logging/subsystem.js", () => ({ createSubsystemLogger: () => logMocks }));

describe("project memory bootstrap", () => {
  beforeEach(() => {
    runtimeMocks.getManager.mockReset();
    runtimeMocks.getProvider.mockReset();
    runtimeMocks.listCurated.mockReset();
    runtimeMocks.search.mockReset();
    runtimeMocks.legacyRuntime = { getMemorySearchManager: runtimeMocks.getManager };
    runtimeMocks.providerRuntime = undefined;
  });

  const entries: MemorySearchResult[] = [
    {
      path: "MEMORY.md",
      startLine: 2,
      endLine: 2,
      score: 0.8,
      snippet:
        "Use the release helper. <!-- trigger: release helper --> <!-- importance: 8 --> <!-- project: github.com/OpenClaw/OpenClaw -->",
      source: "memory" as const,
      projectKey: "github.com/OpenClaw/OpenClaw",
      importance: 8,
      provenance: {
        originClass: "owner" as const,
        sessionKind: "interactive" as const,
        observedAt: 1,
      },
    },
    {
      path: "MEMORY.md",
      startLine: 3,
      endLine: 3,
      score: 0.9,
      snippet: "Foreign fact.",
      source: "memory" as const,
      projectKey: "github.com/example/other",
      importance: 10,
      provenance: {
        originClass: "owner" as const,
        sessionKind: "interactive" as const,
        observedAt: 1,
      },
    },
  ];

  async function prepareEntries(
    candidates: typeof entries,
    activeProjectKeys: string[] = ["github.com/OpenClaw/OpenClaw"],
  ): Promise<string[]> {
    runtimeMocks.listCurated.mockResolvedValue(candidates);
    runtimeMocks.getManager.mockResolvedValue({
      manager: { listCuratedProjectCandidates: runtimeMocks.listCurated },
    });
    return await prepareProjectMemoryBootstrap({ cfg: {}, agentId: "main", activeProjectKeys });
  }

  it("includes only active-project entries and stays inside its budget", async () => {
    const lines = await prepareEntries([
      ...entries,
      {
        ...entries[0]!,
        startLine: 4,
        snippet: "Untrusted project instruction.",
        provenance: {
          originClass: "untrusted",
          sessionKind: "interactive",
          observedAt: 1,
        },
      },
      {
        ...entries[0]!,
        startLine: 5,
        snippet: "Missing-provenance project instruction.",
        provenance: undefined,
      },
    ]);
    const rendered = lines.join("\n");
    expect(rendered).toContain("Use the release helper.");
    expect(rendered).not.toContain("Foreign fact");
    expect(rendered).not.toContain("Untrusted project instruction");
    expect(rendered).not.toContain("Missing-provenance project instruction");
    expect(rendered).not.toContain("<!--");
    expect(rendered.length).toBeLessThanOrEqual(2_000);
  });

  it("includes entries from every project retained in the session active set", async () => {
    const rendered = (
      await prepareEntries(entries, ["github.com/example/other", "github.com/OpenClaw/OpenClaw"])
    ).join("\n");
    expect(rendered).toContain("Use the release helper.");
    expect(rendered).toContain("Foreign fact.");
  });

  it("never emits a partial entry or exceeds the hard budget", async () => {
    const crowded = Array.from({ length: 10 }, (_, index) => ({
      ...entries[0]!,
      startLine: index + 1,
      snippet: `${String(index)} ${"bounded entry ".repeat(50)}`,
    }));
    const lines = await prepareEntries(crowded);
    expect(lines.join("\n").length).toBeLessThanOrEqual(2_000);
    expect(lines.slice(2, -1).every((line) => /\(Source: MEMORY\.md#L\d+\)$/u.test(line))).toBe(
      true,
    );
  });

  it("truncates long entries before admission while preserving the hard cap", async () => {
    const rendered = (await prepareEntries([{ ...entries[0]!, snippet: "🧠".repeat(1_000) }])).join(
      "\n",
    );
    expect(rendered).toContain("…");
    expect(rendered.length).toBeLessThanOrEqual(2_000);
  });

  it("admits a later exact-fit entry after skipping an oversized entry", async () => {
    const first = Array.from({ length: 3 }, (_, index) => ({
      ...entries[0]!,
      startLine: index + 1,
      snippet: "a".repeat(550),
    }));
    const prefix = await prepareEntries(first);
    const sourceSuffix = " (Source: MEMORY.md#L5)";
    const remaining = 2_000 - prefix.join("\n").length;
    const lastSnippet = "z".repeat(remaining - "- ".length - sourceSuffix.length - 1);
    const lines = await prepareEntries([
      ...first,
      { ...entries[0]!, startLine: 4, snippet: "b".repeat(600) },
      { ...entries[0]!, startLine: 5, snippet: lastSnippet },
      { ...entries[0]!, startLine: 6, snippet: "Does not fit." },
    ]);

    expect(lines).toEqual([...prefix.slice(0, -1), `- ${lastSnippet}${sourceSuffix}`, ""]);
    expect(lines.join("\n")).toHaveLength(2_000);
  });

  it("keeps sessions without an active repository unchanged", async () => {
    await expect(prepareEntries(entries, [])).resolves.toEqual([]);
    expect(runtimeMocks.getManager).not.toHaveBeenCalled();
    expect(buildProjectMemoryWriteInstruction(undefined)).toBe("");
  });

  it("filters tagged raw entries fail-closed with the all-keys rule", () => {
    const contextFiles = [
      {
        path: "MEMORY.md",
        content: [
          "- Global fact.",
          "- Alpha fact. <!-- project: github.com/acme/Alpha -->",
          "- Shared fact. <!-- project: github.com/acme/Alpha; github.com/acme/Beta -->",
          "- Invalid fact. <!-- project: github.com/acme/Beta< -->",
          "- Mixed invalid fact. <!-- project: github.com/acme/Alpha; bad< -->",
          "- Unterminated fact. <!-- project: github.com/acme/Alpha",
        ].join("\n"),
      },
    ];
    const empty = filterProjectScopedCuratedContextFiles({ contextFiles });
    const alpha = filterProjectScopedCuratedContextFiles({
      contextFiles,
      activeProjectKeys: ["github.com/acme/Alpha"],
    });
    const both = filterProjectScopedCuratedContextFiles({
      contextFiles,
      activeProjectKeys: ["github.com/acme/Alpha", "github.com/acme/Beta"],
    });

    expect(empty[0]?.content).toBe("- Global fact.");
    expect(alpha[0]?.content).toContain("Alpha fact");
    expect(alpha[0]?.content).not.toContain("Shared fact");
    expect(alpha[0]?.content).not.toContain("Invalid fact");
    expect(alpha[0]?.content).not.toContain("Mixed invalid fact");
    expect(alpha[0]?.content).not.toContain("Unterminated fact");
    expect(both[0]?.content).toContain("Shared fact");
    expect(both[0]?.content).not.toContain("Invalid fact");
    expect(both[0]?.content).not.toContain("Mixed invalid fact");
    expect(both[0]?.content).not.toContain("Unterminated fact");
  });

  it("leaves context files with missing or blank paths for the prompt renderer to ignore", () => {
    const contextFiles = [
      { path: undefined as unknown as string, content: "Missing path" },
      { path: "   ", content: "Blank path" },
    ];

    expect(filterProjectScopedCuratedContextFiles({ contextFiles })).toEqual(contextFiles);
  });

  it("uses the dedicated curated listing instead of a daily-note-crowded search", async () => {
    runtimeMocks.search.mockResolvedValue(
      Array.from({ length: 100 }, (_, index) => ({
        ...entries[0]!,
        path: `memory/2026-07-${String(index + 1).padStart(2, "0")}.md`,
      })),
    );
    runtimeMocks.listCurated.mockResolvedValue([entries[0]]);
    runtimeMocks.getManager.mockResolvedValue({
      manager: {
        search: runtimeMocks.search,
        listCuratedProjectCandidates: runtimeMocks.listCurated,
      },
    });

    const rendered = (
      await prepareProjectMemoryBootstrap({
        cfg: {},
        agentId: "main",
        activeProjectKeys: ["github.com/OpenClaw/OpenClaw"],
      })
    ).join("\n");
    expect(rendered).toContain("Use the release helper.");
    expect(runtimeMocks.search).not.toHaveBeenCalled();
    expect(runtimeMocks.listCurated).toHaveBeenCalledWith({
      activeProjectKeys: ["github.com/OpenClaw/OpenClaw"],
      limit: 48,
    });
  });

  it("builds scoped write guidance without capturing global memory", () => {
    const instruction = buildProjectMemoryWriteInstruction("github.com/OpenClaw/OpenClaw");
    expect(instruction).toContain("<!-- project: github.com/OpenClaw/OpenClaw -->");
    expect(instruction).toContain("Do not project-scope user-level preferences");
    expect(buildProjectMemoryWriteInstruction("path:/tmp/unsafe-->note")).toBe("");
  });

  it("cites legacy chunks by start line from the already-loaded runtime", async () => {
    const startedAt = Date.now();
    const lines = await prepareEntries([
      { ...entries[0]!, startLine: 5, endLine: 6, source: undefined as never },
    ]);

    const finishedAt = Date.now();
    expect(runtimeMocks.getManager).toHaveBeenCalledOnce();
    expect(runtimeMocks.getManager).toHaveBeenCalledWith({
      cfg: {},
      agentId: "main",
      purpose: "default",
      admission: { signal: undefined, deadlineMs: expect.any(Number) },
    });
    const { admission } = runtimeMocks.getManager.mock.calls[0]![0];
    expect(admission.deadlineMs).toBeGreaterThanOrEqual(startedAt + 1_000);
    expect(admission.deadlineMs).toBeLessThanOrEqual(finishedAt + 1_000);
    expect(runtimeMocks.getProvider).not.toHaveBeenCalled();
    expect(lines).toContain("- Use the release helper. (Source: MEMORY.md#L5)");
  });

  it("does not load the slot plugin when no memory runtime is active", async () => {
    runtimeMocks.legacyRuntime = undefined;

    await expect(prepareEntries([entries[0]!])).resolves.toEqual([]);
    expect(runtimeMocks.getManager).not.toHaveBeenCalled();
    expect(runtimeMocks.getProvider).not.toHaveBeenCalled();
  });
});

describe("native project memory bootstrap", () => {
  beforeEach(() => {
    runtimeMocks.getProvider.mockReset();
    runtimeMocks.listCurated.mockReset();
    runtimeMocks.search.mockReset();
    logMocks.debug.mockReset();
    runtimeMocks.legacyRuntime = undefined;
    runtimeMocks.providerRuntime = { open: vi.fn() };
  });

  const entries: MemorySearchHit[] = [
    {
      reference: { providerId: "records", id: "release" },
      excerpt: "Use the release helper.",
      score: 0.8,
      automaticRecall: {
        eligible: true,
        projectKeys: ["github.com/OpenClaw/OpenClaw"],
        importance: 8,
      },
    },
    {
      reference: { providerId: "records", id: "foreign" },
      excerpt: "Foreign fact.",
      score: 0.9,
      automaticRecall: {
        eligible: true,
        projectKeys: ["github.com/example/other"],
        importance: 10,
      },
    },
  ];
  async function prepareEntries(
    candidates: MemorySearchHit[],
    activeProjectKeys = ["github.com/OpenClaw/OpenClaw"],
  ): Promise<string[]> {
    runtimeMocks.listCurated.mockResolvedValue({ hits: candidates });
    runtimeMocks.getProvider.mockResolvedValue({
      provider: {
        capabilities: { candidates: ["project"] },
        candidates: runtimeMocks.listCurated,
        close: vi.fn(),
      },
    });
    return prepareProjectMemoryBootstrap({ cfg: {}, agentId: "main", activeProjectKeys });
  }

  it("includes only active-project entries and stays inside its budget", async () => {
    const lines = await prepareEntries([
      ...entries,
      {
        ...entries[0]!,
        excerpt: "Untrusted project instruction.",
        automaticRecall: { eligible: false, projectKeys: ["github.com/OpenClaw/OpenClaw"] },
      },
      {
        ...entries[0]!,
        excerpt: "Missing-provenance project instruction.",
        automaticRecall: undefined,
      },
    ]);
    const rendered = lines.join("\n");
    expect(rendered).toContain("Use the release helper.");
    expect(rendered).not.toContain("Foreign fact");
    expect(rendered).not.toContain("Untrusted project instruction");
    expect(rendered).not.toContain("Missing-provenance project instruction");
    expect(rendered).not.toContain("<!--");
    expect(rendered.length).toBeLessThanOrEqual(2_000);
  });

  it("includes entries from every project retained in the session active set", async () => {
    const rendered = (
      await prepareEntries(entries, ["github.com/example/other", "github.com/OpenClaw/OpenClaw"])
    ).join("\n");
    expect(rendered).toContain("Use the release helper.");
    expect(rendered).toContain("Foreign fact.");
  });

  it("filters every project key without requesting unsupported provider filtering", async () => {
    runtimeMocks.getProvider.mockResolvedValue({
      provider: {
        capabilities: { candidates: ["trigger", "project"], projectFilter: false },
        candidates: runtimeMocks.listCurated,
        close: vi.fn(),
      },
    });
    runtimeMocks.listCurated.mockResolvedValue({
      hits: [
        {
          ...entries[0]!,
          automaticRecall: { eligible: true, projectKeys: ["alpha", "beta"] },
        },
        {
          ...entries[1]!,
          automaticRecall: { eligible: true, projectKeys: ["alpha", "inactive"] },
        },
      ],
    });

    const rendered = (
      await prepareProjectMemoryBootstrap({
        cfg: {},
        agentId: "main",
        activeProjectKeys: ["alpha", "beta"],
      })
    ).join("\n");

    expect(runtimeMocks.listCurated).toHaveBeenCalledExactlyOnceWith({
      kind: "project",
      limit: 48,
    });
    expect(rendered).toContain("Use the release helper.");
    expect(rendered).not.toContain("Foreign fact.");
  });

  it("uses the dedicated curated listing instead of a daily-note-crowded search", async () => {
    runtimeMocks.search.mockResolvedValue(
      Array.from({ length: 100 }, (_, index) => ({
        ...entries[0]!,
        path: `memory/2026-07-${String(index + 1).padStart(2, "0")}.md`,
      })),
    );
    runtimeMocks.listCurated.mockResolvedValue({ hits: [entries[0]] });
    runtimeMocks.getProvider.mockResolvedValue({
      provider: {
        capabilities: { candidates: ["project"], projectFilter: true },
        search: runtimeMocks.search,
        candidates: runtimeMocks.listCurated,
        close: vi.fn(),
      },
    });

    const rendered = (
      await prepareProjectMemoryBootstrap({
        cfg: {},
        agentId: "main",
        activeProjectKeys: ["github.com/OpenClaw/OpenClaw"],
      })
    ).join("\n");
    expect(rendered).toContain("Use the release helper.");
    expect(runtimeMocks.search).not.toHaveBeenCalled();
    expect(runtimeMocks.listCurated).toHaveBeenCalledWith({
      kind: "project",
      activeProjectKeys: ["github.com/OpenClaw/OpenClaw"],
      limit: 48,
    });
  });

  it("skips undeclared project capability and releases its lease", async () => {
    const close = vi.fn();
    runtimeMocks.getProvider.mockResolvedValue({
      provider: {
        capabilities: { candidates: ["trigger"] },
        candidates: runtimeMocks.listCurated,
        close,
      },
    });
    expect(
      await prepareProjectMemoryBootstrap({
        cfg: {},
        agentId: "main",
        activeProjectKeys: ["alpha"],
      }),
    ).toEqual([]);
    expect(runtimeMocks.listCurated).not.toHaveBeenCalled();
    expect(close).toHaveBeenCalledOnce();
  });

  it("omits optional project recall when provider cleanup rejects", async () => {
    const close = vi.fn().mockRejectedValue(new Error("provider cleanup failed"));
    runtimeMocks.getProvider.mockResolvedValue({
      provider: {
        capabilities: { candidates: ["project"] },
        candidates: runtimeMocks.listCurated,
        close,
      },
    });
    runtimeMocks.listCurated.mockResolvedValue({ hits: entries });

    await expect(
      prepareProjectMemoryBootstrap({
        cfg: {},
        agentId: "main",
        activeProjectKeys: ["github.com/OpenClaw/OpenClaw"],
      }),
    ).resolves.toEqual([]);
    expect(runtimeMocks.listCurated).toHaveBeenCalledOnce();
    expect(close).toHaveBeenCalledOnce();
    expect(logMocks.debug).toHaveBeenCalledWith(
      expect.stringContaining(
        "project memory cleanup failed for memory-core: Error: provider cleanup failed",
      ),
    );
  });

  it.each(["selection", "close"])(
    "does not inject records after caller authority is revoked during %s",
    async (during) => {
      let active = true;
      const close = vi.fn(async () => {
        if (during === "close") {
          active = false;
        }
      });
      runtimeMocks.getProvider.mockResolvedValue({
        provider: {
          capabilities: { candidates: ["project"] },
          candidates: runtimeMocks.listCurated,
          close,
        },
      });
      runtimeMocks.listCurated.mockImplementation(async () => {
        if (during === "selection") {
          active = false;
        }
        return { hits: entries };
      });
      expect(
        await prepareProjectMemoryBootstrap({
          cfg: {},
          agentId: "main",
          activeProjectKeys: ["github.com/OpenClaw/OpenClaw"],
          context: {
            authority: { kind: "host", operation: "project-test" },
            assertCurrent() {
              if (!active) {
                throw new Error("revoked");
              }
            },
          },
        }),
      ).toEqual([]);
      expect(close).toHaveBeenCalledOnce();
    },
  );
});

// The existing closed runtime mock isolates host waiting/lease ownership, not provider internals.
describe("project recall total budget and cancellation", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    runtimeMocks.getManager.mockReset();
    runtimeMocks.getProvider.mockReset();
    runtimeMocks.legacyRuntime = undefined;
    runtimeMocks.providerRuntime = { open: vi.fn() };
  });
  afterEach(() => vi.useRealTimers());

  const params = { cfg: {}, agentId: "main", activeProjectKeys: ["alpha"] };
  const context = (signal: AbortSignal) => ({
    authority: { kind: "host" as const, operation: "project-budget-test" },
    signal,
    assertCurrent() {},
  });
  const gate = () => {
    let resolve!: () => void;
    const promise = new Promise<void>((accept) => {
      resolve = accept;
    });
    return { promise, resolve };
  };

  it.each(["empty", "no-runtime", "native"])("preserves pre-abort reason on %s", async (route) => {
    const caller = new AbortController();
    const reason = { canceled: route };
    caller.abort(reason);
    if (route === "no-runtime") {
      runtimeMocks.providerRuntime = undefined;
    }
    await expect(
      prepareProjectMemoryBootstrap({
        ...params,
        activeProjectKeys: route === "empty" ? [] : params.activeProjectKeys,
        context: context(caller.signal),
      }),
    ).rejects.toBe(reason);
    expect(runtimeMocks.getProvider).not.toHaveBeenCalled();
    expect(vi.getTimerCount()).toBe(0);
  });

  it.each(["open", "candidates", "close"])(
    "bounds hanging native %s and releases the eventual lease once",
    async (stage) => {
      const blocked = gate();
      const entered = gate();
      const released = gate();
      const close = vi.fn(async () => {
        if (stage === "close") {
          entered.resolve();
          await blocked.promise;
        }
        released.resolve();
      });
      const candidates = vi.fn(async () => {
        if (stage === "candidates") {
          entered.resolve();
          await blocked.promise;
        }
        return {
          hits: [
            {
              reference: { providerId: "records", id: "late" },
              excerpt: "Late result must not enter prompt",
              automaticRecall: { eligible: true, projectKeys: ["alpha"] },
            },
          ],
        };
      });
      runtimeMocks.getProvider.mockImplementation(async () => {
        if (stage === "open") {
          entered.resolve();
          await blocked.promise;
        }
        return { provider: { capabilities: { candidates: ["project"] }, candidates, close } };
      });
      const pending = prepareProjectMemoryBootstrap(params);
      await entered.promise;
      await vi.advanceTimersByTimeAsync(1_000);
      await expect(pending).resolves.toEqual([]);
      blocked.resolve();
      await released.promise;
      expect(close).toHaveBeenCalledOnce();
      if (stage === "open") {
        expect(candidates).not.toHaveBeenCalled();
      }
      expect(vi.getTimerCount()).toBe(0);
    },
  );

  it.each(["open", "candidates", "close"])(
    "propagates real parent abort during %s without abandoning late release",
    async (stage) => {
      const caller = new AbortController();
      const blocked = gate();
      const entered = gate();
      const released = gate();
      const reason = { source: "parent", stage };
      const close = vi.fn(async () => {
        if (stage === "close") {
          entered.resolve();
          await blocked.promise;
        }
        released.resolve();
      });
      const candidates = vi.fn(async () => {
        if (stage === "candidates") {
          entered.resolve();
          await blocked.promise;
        }
        return {
          hits: [
            {
              reference: { providerId: "records", id: "late" },
              excerpt: "Late result must not enter prompt",
              automaticRecall: { eligible: true, projectKeys: ["alpha"] },
            },
          ],
        };
      });
      runtimeMocks.getProvider.mockImplementation(async ({ context: callerContext }) => {
        expect(callerContext.signal).toBe(caller.signal);
        if (stage === "open") {
          entered.resolve();
          await blocked.promise;
        }
        return { provider: { capabilities: { candidates: ["project"] }, candidates, close } };
      });
      const pending = prepareProjectMemoryBootstrap({ ...params, context: context(caller.signal) });
      const checked = expect(pending).rejects.toBe(reason);
      await entered.promise;
      caller.abort(reason);
      await checked;
      blocked.resolve();
      await released.promise;
      expect(close).toHaveBeenCalledOnce();
      expect(vi.getTimerCount()).toBe(0);
    },
  );

  it("lets observable parent cancellation beat same-tick deadline fallback", async () => {
    const caller = new AbortController();
    const reason = new Error("parent canceled");
    const blocked = gate();
    runtimeMocks.providerRuntime = undefined;
    runtimeMocks.legacyRuntime = { getMemorySearchManager: runtimeMocks.getManager };
    runtimeMocks.getManager.mockImplementation(async () => {
      await blocked.promise;
      return { manager: null };
    });
    setTimeout(() => caller.abort(reason), 1_000);
    const pending = prepareProjectMemoryBootstrap({ ...params, context: context(caller.signal) });
    const checked = expect(pending).rejects.toBe(reason);
    await vi.advanceTimersByTimeAsync(1_000);
    await checked;
    blocked.resolve();
  });

  it("passes the original absolute deadline and never closes a borrowed legacy manager", async () => {
    const close = vi.fn();
    const listCuratedProjectCandidates = vi.fn();
    const manager = { close, listCuratedProjectCandidates };
    const entered = gate();
    let resolveManager!: (value: { manager: typeof manager }) => void;
    const managerResult = new Promise<{ manager: typeof manager }>((resolve) => {
      resolveManager = resolve;
    });
    runtimeMocks.providerRuntime = undefined;
    runtimeMocks.legacyRuntime = { getMemorySearchManager: runtimeMocks.getManager };
    const start = Date.now();
    // No assertions in this callback: optional-recall errors are intentionally caught.
    runtimeMocks.getManager.mockImplementation(() => {
      entered.resolve();
      return managerResult;
    });
    const pending = prepareProjectMemoryBootstrap(params);
    await entered.promise;
    expect(runtimeMocks.getManager).toHaveBeenCalledOnce();
    expect(runtimeMocks.getManager).toHaveBeenCalledWith({
      cfg: params.cfg,
      agentId: params.agentId,
      purpose: "default",
      admission: { signal: undefined, deadlineMs: start + 1_000 },
    });
    await vi.advanceTimersByTimeAsync(1_000);
    await expect(pending).resolves.toEqual([]);
    resolveManager({ manager });
    await expect(managerResult).resolves.toEqual({ manager });
    // Drain the loader continuation attached before this late manager resolution.
    await vi.advanceTimersByTimeAsync(0);
    expect(runtimeMocks.getManager).toHaveBeenCalledOnce();
    expect(listCuratedProjectCandidates).not.toHaveBeenCalled();
    expect(close).not.toHaveBeenCalled();
    expect(vi.getTimerCount()).toBe(0);
  });
  it("observes a late host-owned open rejection without claiming its lease", async () => {
    const blocked = gate();
    const entered = gate();
    const released = gate();
    const close = vi.fn(async () => {
      released.resolve();
    });
    // Model memory-runtime's own late-open rejection cleanup: no handle is returned.
    runtimeMocks.getProvider.mockImplementation(async () => {
      entered.resolve();
      await blocked.promise;
      await close();
      throw new Error("host rejected stale caller after cleaning its provider");
    });
    const pending = prepareProjectMemoryBootstrap(params);
    await entered.promise;
    await vi.advanceTimersByTimeAsync(1_000);
    await expect(pending).resolves.toEqual([]);
    blocked.resolve();
    await released.promise;
    await vi.advanceTimersByTimeAsync(0);
    expect(close).toHaveBeenCalledOnce();
    expect(vi.getTimerCount()).toBe(0);
  });
});
