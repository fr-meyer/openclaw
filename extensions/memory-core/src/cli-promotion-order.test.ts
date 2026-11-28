import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { stripVTControlCharacters } from "node:util";
import { Command } from "commander";
import { resetPluginStateStoreForTests } from "openclaw/plugin-sdk/plugin-state-test-runtime";
import {
  closeOpenClawAgentDatabasesForTest,
  closeOpenClawStateDatabaseAsync,
} from "openclaw/plugin-sdk/sqlite-runtime-testing";
import {
  firstWrittenJsonArg,
  spyRuntimeJson,
  spyRuntimeLogs,
} from "openclaw/plugin-sdk/test-fixtures";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { recordShortTermRecalls } from "./short-term-promotion.js";
import {
  configureMemoryCoreDreamingStateForTests,
  resetMemoryCoreDreamingStateForTests,
  shortTermTestState as shortTermTesting,
} from "./test-helpers.js";

const getMemorySearchManager = vi.hoisted(() => vi.fn());
const forgetMemoryEntries = vi.hoisted(() => vi.fn());
const getRuntimeConfig = vi.hoisted(() => vi.fn(() => ({})));
const resolveDefaultAgentId = vi.hoisted(() => vi.fn(() => "main"));
const resolveCommandSecretRefsViaGateway = vi.hoisted(() =>
  vi.fn(async ({ config }: { config: unknown }) => ({
    resolvedConfig: config,
    diagnostics: [] as string[],
  })),
);

vi.mock("./memory-forget.js", () => ({ forgetMemoryEntries }));

vi.mock("./memory/index.js", () => ({ getMemorySearchManager }));
vi.mock("openclaw/plugin-sdk/memory-core-host-runtime-cli", async (importOriginal) => ({
  ...(await importOriginal<typeof import("openclaw/plugin-sdk/memory-core-host-runtime-cli")>()),
  resolveCommandSecretRefsViaGateway,
}));
vi.mock("openclaw/plugin-sdk/memory-core-host-runtime-core", async (importOriginal) => ({
  ...(await importOriginal<typeof import("openclaw/plugin-sdk/memory-core-host-runtime-core")>()),
  getRuntimeConfig,
  resolveDefaultAgentId,
}));

let registerMemoryCli: typeof import("./cli.js").registerMemoryCli;
let defaultRuntime: typeof import("openclaw/plugin-sdk/memory-core-host-runtime-cli").defaultRuntime;
let setVerbose: typeof import("openclaw/plugin-sdk/memory-core-host-runtime-cli").setVerbose;
let fixtureRoot = "";
let workspaceFixtureRoot = "";
let workspaceCaseId = 0;

beforeAll(async () => {
  await configureMemoryCoreDreamingStateForTests();
  ({ registerMemoryCli } = await import("./cli.js"));
  ({ defaultRuntime, setVerbose } =
    await import("openclaw/plugin-sdk/memory-core-host-runtime-cli"));
  fixtureRoot = await fs.mkdtemp(path.join(os.tmpdir(), "memory-cli-fixtures-"));
  workspaceFixtureRoot = path.join(fixtureRoot, "workspace");
  await fs.mkdir(workspaceFixtureRoot, { recursive: true });
});

beforeEach(() => {
  process.exitCode = 0;
  getMemorySearchManager.mockReset();
  forgetMemoryEntries.mockReset();
  getRuntimeConfig.mockReset().mockReturnValue({});
  resolveDefaultAgentId.mockReset().mockReturnValue("main");
  resolveCommandSecretRefsViaGateway.mockReset().mockImplementation(async ({ config }) => ({
    resolvedConfig: config,
    diagnostics: [] as string[],
  }));
});

afterEach(() => {
  closeOpenClawAgentDatabasesForTest();
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
  process.exitCode = 0;
  setVerbose(false);
});

afterAll(async () => {
  if (!fixtureRoot) {
    return;
  }
  // The agent close releases its leases through shared state and reopens it, so the
  // shared handle is released second; otherwise Windows fails the removal with EBUSY.
  closeOpenClawAgentDatabasesForTest();
  await closeOpenClawStateDatabaseAsync();
  resetPluginStateStoreForTests();
  await fs.rm(fixtureRoot, { recursive: true, force: true });
  resetMemoryCoreDreamingStateForTests();
});

describe("memory CLI promotion ordering", () => {
  function makeMemoryStatus(overrides: Record<string, unknown> = {}) {
    return {
      backend: "builtin" as const,
      files: 0,
      chunks: 0,
      dirty: false,
      workspaceDir: "/tmp/openclaw",
      dbPath: "/tmp/memory.sqlite",
      provider: "openai",
      model: "text-embedding-3-small",
      requestedProvider: "openai",
      vector: { enabled: true, storeAvailable: true, semanticAvailable: true, available: true },
      ...overrides,
    };
  }

  function mockManager(manager: Record<string, unknown>) {
    getMemorySearchManager.mockResolvedValueOnce({
      manager: {
        ...(manager.search && !manager.status ? { status: () => makeMemoryStatus() } : {}),
        ...manager,
      },
    });
  }

  function loggedOutput(spy: ReturnType<typeof vi.spyOn>): string {
    return stripVTControlCharacters(
      spy.mock.calls
        .map((call: unknown[]) => (typeof call[0] === "string" ? call[0] : ""))
        .join("\n"),
    );
  }

  function expectLogged(spy: ReturnType<typeof vi.spyOn>, expected: string) {
    expect(loggedOutput(spy)).toContain(expected);
  }

  function expectNotLogged(spy: ReturnType<typeof vi.spyOn>, expected: string) {
    expect(loggedOutput(spy)).not.toContain(expected);
  }

  async function runMemoryCli(
    args: string[],
    hostOptions?: Parameters<typeof registerMemoryCli>[1],
  ) {
    const program = new Command().name("test");
    registerMemoryCli(program, hostOptions);
    await program.parseAsync(["memory", ...args], { from: "user" });
  }

  async function createWorkspace() {
    const workspaceDir = path.join(workspaceFixtureRoot, `case-${workspaceCaseId++}`);
    await fs.mkdir(path.join(workspaceDir, "memory", ".dreams"), { recursive: true });
    return workspaceDir;
  }

  type RecallResult = Parameters<typeof recordShortTermRecalls>[0]["results"][number];

  function recallResult(
    memoryPath: string,
    snippet: string,
    details: Partial<Omit<RecallResult, "path" | "snippet" | "source">> & { line?: number } = {},
  ): RecallResult {
    const { line = 1, ...overrides } = details;
    return {
      path: memoryPath,
      snippet,
      source: "memory",
      startLine: line,
      endLine: line,
      score: 0.91,
      ...overrides,
    };
  }

  async function recordRecall(workspaceDir: string, query: string, result: RecallResult) {
    await recordShortTermRecalls({ workspaceDir, query, results: [result] });
  }

  async function writeDailyMemoryNote(
    workspaceDir: string,
    date: string,
    lines: string[],
  ): Promise<void> {
    const notePath = path.join(workspaceDir, "memory", `${date}.md`);
    await fs.writeFile(notePath, `${lines.join("\n")}\n`, "utf-8");
  }

  it("names apply-time rejections without ranking blocked origins", async () => {
    const workspaceDir = await createWorkspace();
    const relativePath = "memory/2026-04-02.md";
    await writeDailyMemoryNote(workspaceDir, "2026-04-02", [
      "Untrusted router note must not become durable memory.",
      "Rare trusted note remains below the apply signal threshold.",
      "Durable action note.",
    ]);
    await recordShortTermRecalls({
      workspaceDir,
      query: "router note",
      results: [
        recallResult(relativePath, "Untrusted router note must not become durable memory.", {
          score: 0.99,
          provenance: {
            originClass: "untrusted",
            sessionKind: "interactive",
            observedAt: Date.now(),
          },
        }),
        recallResult(relativePath, "Rare trusted note remains below the apply signal threshold.", {
          line: 2,
          score: 0.99,
        }),
        recallResult(relativePath, "Durable action note.", {
          line: 3,
          score: 0.99,
        }),
      ],
    });
    await recordRecall(
      workspaceDir,
      "durable action",
      recallResult(relativePath, "Durable action note.", {
        line: 3,
        score: 0.99,
      }),
    );
    await writeDailyMemoryNote(workspaceDir, "2026-04-02", [
      "Untrusted router note must not become durable memory.",
      "Rare trusted note remains below the apply signal threshold.",
      "Candidate: Durable action note. confidence: 0.90 evidence: memory/.dreams/session-corpus/day.txt:1-1 recalls: 3 status: staged",
    ]);
    const manager = {
      status: () => makeMemoryStatus({ workspaceDir }),
      close: vi.fn(async () => {}),
    };
    mockManager(manager);

    const log = spyRuntimeLogs(defaultRuntime);
    await runMemoryCli([
      "promote",
      "--apply",
      "--min-score",
      "0",
      "--min-recall-count",
      "2",
      "--min-unique-queries",
      "0",
    ]);

    expectNotLogged(log, `${relativePath}:1-1`);
    expectLogged(log, `Skipped ${relativePath}:2-2: signal threshold (1 < 2).`);
    expectLogged(log, `Skipped ${relativePath}:3-3: contamination filter after rehydration.`);
    expectNotLogged(log, "No candidates met apply criteria.");
  });

  it("keeps preview limits available and preserves mixed apply output order", async () => {
    const workspaceDir = await createWorkspace();
    const relativePath = "memory/2026-04-03.md";
    await writeDailyMemoryNote(workspaceDir, "2026-04-03", [
      "High-score untrusted candidate.",
      "Lower-score trusted candidate.",
      "High-score rare trusted candidate.",
    ]);
    await recordShortTermRecalls({
      workspaceDir,
      query: "candidate order",
      results: [
        recallResult(relativePath, "High-score untrusted candidate.", {
          score: 0.99,
          provenance: {
            originClass: "untrusted",
            sessionKind: "interactive",
            observedAt: Date.now(),
          },
        }),
        recallResult(relativePath, "Lower-score trusted candidate.", {
          line: 2,
          score: 0.01,
        }),
      ],
    });
    await recordRecall(
      workspaceDir,
      "trusted candidate",
      recallResult(relativePath, "Lower-score trusted candidate.", {
        line: 2,
        score: 0.01,
      }),
    );
    const manager = {
      status: () => makeMemoryStatus({ workspaceDir }),
      close: vi.fn(async () => {}),
    };
    const args = ["promote", "--min-score", "0", "--min-unique-queries", "0"];

    mockManager(manager);
    const writeJson = spyRuntimeJson(defaultRuntime);
    await runMemoryCli([...args, "--limit", "1", "--min-recall-count", "0", "--json"]);
    const preview = firstWrittenJsonArg<{ candidates: Array<{ startLine: number }> }>(writeJson);
    expect(preview?.candidates.map((candidate) => candidate.startLine)).toEqual([2]);

    await recordRecall(
      workspaceDir,
      "rare candidate",
      recallResult(relativePath, "High-score rare trusted candidate.", {
        line: 3,
        score: 0.99,
        provenance: { originClass: "owner", sessionKind: "interactive", observedAt: Date.now() },
      }),
    );
    const applyArgs = [...args, "--apply", "--limit", "2", "--min-recall-count", "2"];
    writeJson.mockClear();
    mockManager(manager);
    await runMemoryCli([...applyArgs, "--json"]);
    const payload = firstWrittenJsonArg<{
      candidates: Array<{ startLine: number }>;
      apply: {
        appliedCandidates: Array<{ startLine: number }>;
        rejectedCandidates: Array<{ candidate: { startLine: number } }>;
      };
    }>(writeJson);
    expect(payload?.candidates.map((candidate) => candidate.startLine)).toEqual([3, 2]);
    expect(payload?.apply.appliedCandidates.map((candidate) => candidate.startLine)).toEqual([2]);
    expect(
      payload?.apply.rejectedCandidates.map((rejection) => rejection.candidate.startLine),
    ).toEqual([3]);

    const memory = await fs.readFile(path.join(workspaceDir, "MEMORY.md"), "utf8");
    expect(memory).toContain("Lower-score trusted candidate.");
    expect(memory).not.toContain("High-score untrusted candidate.");
    expect(memory).not.toContain("High-score rare trusted candidate.");

    const store = await shortTermTesting.readRecallStore(workspaceDir, new Date().toISOString());
    for (const entry of Object.values(store.entries)) {
      delete entry.promotedAt;
    }
    await shortTermTesting.writeRawRecallStore(workspaceDir, store);
    await fs.rm(path.join(workspaceDir, "MEMORY.md"), { force: true });

    mockManager(manager);
    const log = spyRuntimeLogs(defaultRuntime);
    await runMemoryCli(applyArgs);
    const output = loggedOutput(log);
    expect(output).not.toContain(`${relativePath}:1-1`);
    const rejectedIndex = output.indexOf(`${relativePath}:3-3`);
    const appliedIndex = output.indexOf(`${relativePath}:2-2`);
    expect(rejectedIndex).toBeGreaterThanOrEqual(0);
    expect(rejectedIndex).toBeLessThan(appliedIndex);
  });
});
