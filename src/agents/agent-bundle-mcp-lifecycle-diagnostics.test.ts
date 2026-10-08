import { Writable } from "node:stream";
import type { JSONRPCMessage } from "@modelcontextprotocol/sdk/types.js";
import { afterEach, beforeEach, expect, expectTypeOf, it, type Mock, vi } from "vitest";
import { createDeferred } from "../../test/helpers/promise.js";
import type { OpenClawConfig } from "../config/types.openclaw.js";
import {
  onInternalDiagnosticEvent,
  resetDiagnosticEventsForTest,
  setDiagnosticsEnabledForProcess,
  waitForDiagnosticEventsDrained,
} from "../infra/diagnostic-events.js";
import {
  getDiagnosticStabilitySnapshot,
  resetDiagnosticStabilityRecorderForTest,
  startDiagnosticStabilityRecorder,
  stopDiagnosticStabilityRecorder,
} from "../logging/diagnostic-stability.js";
import type {
  closeOwnedStdioProcess,
  createOwnedStdioProcess,
  OwnedStdioProcess,
} from "../process/owned-stdio.js";
import type { Deferred } from "../shared/deferred.js";
import { createSessionMcpRuntimeManager } from "./agent-bundle-mcp-manager.js";
import { createSessionMcpRuntime } from "./agent-bundle-mcp-runtime.js";
import type { SessionMcpRuntimeManager } from "./agent-bundle-mcp-types.js";
import { OpenClawStreamableHTTPClientTransport } from "./mcp-http-transport.js";
import { OpenClawStdioClientTransport } from "./mcp-stdio-transport.js";

const { spawn, cleanup, resolveTransport } = vi.hoisted(() => ({
  spawn: vi.fn<typeof createOwnedStdioProcess>(),
  cleanup: vi.fn<typeof closeOwnedStdioProcess>(),
  resolveTransport: vi.fn(),
}));
vi.mock("../process/owned-stdio.js", () => ({
  createOwnedStdioProcess: spawn,
  closeOwnedStdioProcess: cleanup,
  OwnedStdioCleanupError: class extends Error {},
}));
vi.mock("./mcp-transport.js", () => ({ resolveMcpTransport: resolveTransport }));
vi.mock("./embedded-agent-mcp.js", () => ({
  loadEmbeddedAgentMcpConfig: ({ cfg }: { cfg?: OpenClawConfig }) => ({
    mcpServers: cfg?.mcp?.servers ?? {},
    diagnostics: [],
    prepareDataDirsByServer: {},
  }),
}));

type ChildExit = Awaited<ReturnType<OwnedStdioProcess["wait"]>>;
type ChildFixture = {
  child: OwnedStdioProcess & {
    pid: number;
    stdin: Writable;
    kill: Mock<OwnedStdioProcess["kill"]>;
    dispose: Mock<OwnedStdioProcess["dispose"]>;
  };
  root: Deferred<ChildExit>;
  send: (message: JSONRPCMessage) => void;
};

const managers: SessionMcpRuntimeManager[] = [];
const children: ChildFixture[] = [];
const transports: OpenClawStdioClientTransport[] = [];
const releases: Array<() => void> = [];
let failInitialize = false;
let holdInitialize = false;
let initializeEntered = createDeferred();
const serverName = "synthetic-private-alias";
const params = {
  sessionId: "synthetic-private-session",
  workspaceDir: "/synthetic/private/workspace",
  cfg: {
    plugins: { enabled: false },
    mcp: { servers: { [serverName]: { command: "synthetic-command" } } },
  } satisfies OpenClawConfig,
};

function makeChild(): ChildFixture {
  const root = createDeferred<ChildExit>();
  let receive: ((chunk: Buffer) => void) | undefined;
  const send = (message: JSONRPCMessage) => receive?.(Buffer.from(JSON.stringify(message) + "\n"));
  const stdin = new Writable({
    write(chunk, _encoding, done) {
      const message = JSON.parse(chunk.toString()) as {
        id?: number;
        method: string;
        params?: { protocolVersion?: string };
      };
      if (message.id !== undefined) {
        if (message.method === "initialize") {
          initializeEntered.resolve();
          if (holdInitialize) {
            done();
            return;
          }
        }
        const response: JSONRPCMessage =
          failInitialize && message.method === "initialize"
            ? {
                jsonrpc: "2.0",
                id: message.id,
                error: { code: -32603, message: "synthetic private error" },
              }
            : {
                jsonrpc: "2.0",
                id: message.id,
                result:
                  message.method === "initialize"
                    ? {
                        protocolVersion: message.params?.protocolVersion,
                        capabilities: { tools: { listChanged: true } },
                        serverInfo: { name: "fixture", version: "1" },
                      }
                    : message.method === "tools/list"
                      ? { tools: [{ name: "probe", inputSchema: { type: "object" } }] }
                      : { content: [] },
              };
        queueMicrotask(() => send(response));
      }
      done();
    },
  });
  const pid: number = 9001 + children.length;
  const child: ChildFixture["child"] = {
    pid,
    stdin,
    supportsRawOutput: true,
    onStdout: (_text: (text: string) => void, raw?: (chunk: Buffer) => void) => {
      receive = raw;
    },
    onStderr: () => {},
    onExit: (listener) => {
      void root.promise.then(({ code, signal }) => listener(code, signal));
    },
    onError: () => {},
    wait: () => root.promise,
    kill: vi.fn<OwnedStdioProcess["kill"]>(),
    dispose: vi.fn<OwnedStdioProcess["dispose"]>(),
  };
  const fixture = { child, root, send };
  children.push(fixture);
  return fixture;
}

// The agents-root compiler graph checks these contracts; Vitest alone does not.
expectTypeOf<ReturnType<typeof makeChild>>().not.toBeAny();
expectTypeOf<(typeof children)[number]>().not.toBeAny();
expectTypeOf<(typeof children)[number]>().toEqualTypeOf<ReturnType<typeof makeChild>>();
expectTypeOf<ReturnType<typeof makeChild>["child"]>().not.toBeAny();
expectTypeOf<ReturnType<typeof makeChild>["child"]>().toExtend<OwnedStdioProcess>();
expectTypeOf<ReturnType<typeof makeChild>["root"]["promise"]>().toEqualTypeOf<
  ReturnType<OwnedStdioProcess["wait"]>
>();

async function events() {
  await waitForDiagnosticEventsDrained();
  return getDiagnosticStabilitySnapshot({ type: "mcp.lifecycle", limit: 1000 }).events;
}

beforeEach(() => {
  resetDiagnosticEventsForTest();
  resetDiagnosticStabilityRecorderForTest();
  startDiagnosticStabilityRecorder();
  failInitialize = false;
  holdInitialize = false;
  initializeEntered = createDeferred();
  spawn.mockImplementation(async () => makeChild().child);
  cleanup.mockResolvedValue(undefined);
  resolveTransport.mockImplementation(() => {
    const transport = new OpenClawStdioClientTransport({ command: "synthetic-command" });
    transports.push(transport);
    return {
      transport,
      description: "synthetic private launch",
      transportType: "stdio",
      connectionTimeoutMs: 1000,
      requestTimeoutMs: 1000,
      supportsParallelToolCalls: true,
    };
  });
});

afterEach(async () => {
  for (const release of releases.splice(0)) {
    release();
  }
  cleanup.mockResolvedValue(undefined);
  for (const { root, child } of children.splice(0)) {
    root.resolve({ code: 0, signal: null });
    child.stdin.destroy();
  }
  await Promise.allSettled(managers.splice(0).map((manager) => manager.disposeAll()));
  await Promise.allSettled(transports.splice(0).map((transport) => transport.close()));
  await waitForDiagnosticEventsDrained();
  stopDiagnosticStabilityRecorder();
  resetDiagnosticStabilityRecorderForTest();
  resetDiagnosticEventsForTest();
  vi.restoreAllMocks();
  spawn.mockReset();
  cleanup.mockReset();
  resolveTransport.mockReset();
});

it.each([false, true])(
  "records lease reuse, refresh and retirement intent (required=%s)",
  async (required) => {
    const manager = createSessionMcpRuntimeManager({
      createRuntime: createSessionMcpRuntime,
      enableIdleSweepTimer: false,
    });
    managers.push(manager);
    const first = await manager.acquire(params);
    expect((await first.runtime.getCatalog()).tools).toHaveLength(1);
    manager.deferRetirement(params.sessionId, { retainAcrossReuse: required });
    const second = await manager.acquire(params);
    await second.runtime.getCatalog();
    children[0]!.send({ jsonrpc: "2.0", method: "notifications/tools/list_changed" });
    await first.runtime.getCatalog();
    first.releaseLease();
    first.releaseLease();
    second.releaseLease();
    second.releaseLease();
    if (required) {
      await manager.completeDeferredRetirement(params.sessionId);
    } else {
      await manager.disposeAll();
    }
    const records = await events();
    expect(new Set(records.map((record) => record.mcp?.generationId)).size).toBe(1);
    const connected = records.find((record) => record.phase === "connected");
    expect(connected?.mcp).toMatchObject({
      childPid: 9001,
      serverRuntimeActiveLeases: 1,
      connected: true,
      providerClass: "stdio",
    });
    expect(
      records
        .filter((record) => record.phase === "lease")
        .map((record) => record.mcp?.serverRuntimeActiveLeases),
    ).toEqual([2, 1, 0]);
    expect(
      records
        .filter((record) => record.phase === "retirement")
        .map((record) => record.mcp?.retirementIntent),
    ).toContain(required ? "required" : "deferred");
    if (!required) {
      expect(
        records.some(
          (record) => record.phase === "retirement" && record.mcp?.retirementIntent === "none",
        ),
      ).toBe(true);
    }
    expect(records.at(-1)?.mcp).toMatchObject({
      closeOutcome: "closed",
      childPid: 9001,
      serverRuntimeActiveLeases: 0,
      retirementIntent: required ? "required" : "none",
    });
    expect(cleanup).toHaveBeenCalledTimes(1);
    expect(JSON.stringify(records)).not.toMatch(
      /synthetic-private|synthetic private|synthetic-command|\/workspace/,
    );
  },
);

it("keeps required intent armed before a lazy transport is first created", async () => {
  const manager = createSessionMcpRuntimeManager({
    createRuntime: createSessionMcpRuntime,
    enableIdleSweepTimer: false,
  });
  managers.push(manager);
  expect(manager.deferRetirement(params.sessionId, { retainAcrossReuse: true })).toBe(true);
  const lease = await manager.acquire(params);
  await lease.runtime.getCatalog();
  expect(
    (await events()).find((record) => record.phase === "connected")?.mcp?.retirementIntent,
  ).toBe("required");
  lease.releaseLease();
  await manager.completeDeferredRetirement(params.sessionId);
});

it("does not certify cleanup from a root close and rotates identity on reconnect", async () => {
  const manager = createSessionMcpRuntimeManager({
    createRuntime: createSessionMcpRuntime,
    enableIdleSweepTimer: false,
  });
  managers.push(manager);
  const lease = await manager.acquire(params);
  await lease.runtime.getCatalog();
  const gate = createDeferred<undefined>();
  cleanup.mockImplementationOnce(() => gate.promise);
  children[0]!.root.resolve({ code: 0, signal: null });
  const before = await events();
  expect(before.at(-1)?.phase).toBe("transport-closed");
  expect(before.at(-1)?.mcp).toMatchObject({
    connected: false,
    closeOutcome: "not-requested",
    childPid: 9001,
  });
  const catalog = lease.runtime.getCatalog();
  gate.resolve(undefined);
  await catalog;
  const after = await events();
  const connections = after.filter((record) => record.phase === "connected");
  expect(connections).toHaveLength(2);
  expect(connections[0]?.mcp?.generationId).not.toBe(connections[1]?.mcp?.generationId);
  expect(connections[1]?.mcp?.childPid).toBe(9002);
  expect(after.find((record) => record.phase === "cleanup")?.mcp).toMatchObject({
    generationId: connections[0]?.mcp?.generationId,
    closeOutcome: "closed",
    childPid: 9001,
  });
  expect(transports[0]!.pid).toBeNull();
  expect(transports[0]!.diagnosticPid).toBe(9001);
  lease.releaseLease();
});

it.each([false, true])(
  "retains failed-initialize PID and cleanup outcome (failure=%s)",
  async (failure) => {
    failInitialize = true;
    if (failure) {
      cleanup.mockRejectedValue(new Error("synthetic private cleanup error"));
    }
    const manager = createSessionMcpRuntimeManager({
      createRuntime: createSessionMcpRuntime,
      enableIdleSweepTimer: false,
    });
    managers.push(manager);
    const lease = await manager.acquire(params);
    const catalog = await lease.runtime.getCatalog();
    expect(catalog.tools).toEqual([]);
    const records = await events();
    expect(records.filter((record) => record.phase === "cleanup")).toHaveLength(1);
    expect(records.at(-1)?.mcp).toMatchObject({
      childPid: 9001,
      connected: false,
      closeOutcome: failure ? "uncertain" : "closed",
    });
    if (failure) {
      await expect(lease.runtime.joinCleanup?.()).rejects.toThrow("could not confirm closure");
    }
    expect(JSON.stringify(records)).not.toContain("synthetic private");
    lease.releaseLease();
  },
);

it("keeps MCP behavior unchanged when diagnostics are disabled", async () => {
  setDiagnosticsEnabledForProcess(false);
  const manager = createSessionMcpRuntimeManager({
    createRuntime: createSessionMcpRuntime,
    enableIdleSweepTimer: false,
  });
  managers.push(manager);
  const lease = await manager.acquire(params);
  expect((await lease.runtime.getCatalog()).tools).toHaveLength(1);
  lease.releaseLease();
  await manager.disposeAll();
  expect(await events()).toEqual([]);
  expect(cleanup).toHaveBeenCalledTimes(1);
});

it("retains PID when the initialize deadline closes the transport before catalog failure", async () => {
  holdInitialize = true;
  const deadline = new AbortController();
  vi.spyOn(AbortSignal, "timeout").mockReturnValue(deadline.signal);
  const manager = createSessionMcpRuntimeManager({
    createRuntime: createSessionMcpRuntime,
    enableIdleSweepTimer: false,
  });
  managers.push(manager);
  const lease = await manager.acquire(params);
  const catalog = lease.runtime.getCatalog();
  await initializeEntered.promise;
  deadline.abort(new DOMException("synthetic deadline", "TimeoutError"));
  expect((await catalog).tools).toEqual([]);
  const records = await events();
  expect(records.at(-1)?.mcp).toMatchObject({
    childPid: 9001,
    connected: false,
    closeOutcome: "closed",
  });
  expect(transports[0]!.pid).toBeNull();
  expect(cleanup).toHaveBeenCalledTimes(1);
  lease.releaseLease();
});

it("keeps a delayed old close separate from replacement leases and cleanup", async () => {
  const oldDelete = createDeferred();
  releases.push(() => oldDelete.resolve());
  const deleteEntered = createDeferred();
  const replacementConnected = createDeferred();
  let connectedCount = 0;
  releases.push(
    onInternalDiagnosticEvent(
      (event) => {
        if (event.type === "mcp.lifecycle" && event.phase === "connected") {
          connectedCount += 1;
          if (connectedCount === 2) {
            replacementConnected.resolve();
          }
        }
      },
      { includeTrusted: ["mcp.lifecycle"] },
    ),
  );
  let nextTransport = 0;
  resolveTransport.mockImplementation(() => {
    const index = ++nextTransport;
    const transport = new OpenClawStreamableHTTPClientTransport(
      new URL("https://synthetic.invalid/private"),
      {
        fetch: async (_input, init) => {
          if (init?.method === "DELETE") {
            if (index === 1) {
              deleteEntered.resolve();
              await oldDelete.promise;
            }
            return new Response(null, { status: 200 });
          }
          if (init?.method !== "POST" || typeof init.body !== "string") {
            return new Response(null, { status: 405 });
          }
          const message = JSON.parse(init.body) as {
            id?: number;
            method: string;
            params?: { protocolVersion?: string };
          };
          if (message.method === "tools/call" && index === 1) {
            return new Response("Expired", { status: 404 });
          }
          if (message.id === undefined) {
            return new Response(null, { status: 202 });
          }
          return new Response(
            JSON.stringify({
              jsonrpc: "2.0",
              id: message.id,
              result:
                message.method === "initialize"
                  ? {
                      protocolVersion: message.params?.protocolVersion,
                      capabilities: { tools: {} },
                      serverInfo: { name: "fixture", version: "1" },
                    }
                  : message.method === "tools/list"
                    ? { tools: [{ name: "probe", inputSchema: { type: "object" } }] }
                    : { content: [] },
            }),
            {
              headers: {
                "content-type": "application/json",
                "mcp-session-id": "synthetic-" + index,
              },
            },
          );
        },
      },
    );
    return {
      transport,
      description: "synthetic private launch",
      transportType: "streamable-http",
      connectionTimeoutMs: 1000,
      requestTimeoutMs: 1000,
      supportsParallelToolCalls: true,
    };
  });
  const manager = createSessionMcpRuntimeManager({
    createRuntime: createSessionMcpRuntime,
    enableIdleSweepTimer: false,
  });
  managers.push(manager);
  const first = await manager.acquire(params);
  await first.runtime.getCatalog();
  await expect(first.runtime.callTool(serverName, "probe", {})).rejects.toMatchObject({
    code: 404,
  });
  await deleteEntered.promise;
  expect(await first.runtime.getCatalog()).toMatchObject({
    tools: [expect.objectContaining({ toolName: "probe" })],
  });
  await replacementConnected.promise;
  const second = await manager.acquire(params);
  const during = await events();
  const connected = during.filter((record) => record.phase === "connected");
  expect(connected).toHaveLength(2);
  const oldId = connected[0]!.mcp!.generationId;
  const newId = connected[1]!.mcp!.generationId;
  expect(newId).not.toBe(oldId);
  expect(during.filter((record) => record.phase === "lease").map((record) => record.mcp)).toEqual([
    expect.objectContaining({
      generationId: newId,
      serverRuntimeActiveLeases: 2,
      connected: true,
      closeOutcome: "not-requested",
    }),
    expect.objectContaining({
      generationId: oldId,
      serverRuntimeActiveLeases: 2,
      retiring: true,
      closeOutcome: "pending",
    }),
  ]);
  oldDelete.resolve();
  await first.runtime.joinCleanup?.();
  const after = await events();
  expect(after.filter((record) => record.phase === "cleanup").map((record) => record.mcp)).toEqual([
    expect.objectContaining({
      generationId: oldId,
      providerClass: "streamable-http",
      closeOutcome: "closed",
    }),
  ]);
  await expect(second.runtime.callTool(serverName, "probe", {})).resolves.toMatchObject({
    content: [],
  });
  first.releaseLease();
  second.releaseLease();
});
