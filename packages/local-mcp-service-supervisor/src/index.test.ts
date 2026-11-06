import { describe, expect, it, vi } from "vitest";
import {
  assertOnlyLoopbackListeners,
  assertProcessIdentity,
  buildLocalMcpServiceStartPlan,
  parsePidFile,
  probeLocalMcpHealth,
  redactServiceLogLine,
  validateLocalMcpServiceSpec,
  type LocalMcpServiceSpec,
} from "./index.js";

function fixture(): LocalMcpServiceSpec {
  return {
    id: "example-mcp",
    command: "/opt/example/bin/example-mcp",
    args: ["--transport", "http"],
    cwd: "/var/lib/example-mcp",
    pidFile: "/var/run/example-mcp/service.pid",
    logFile: "/var/log/example-mcp/service.log",
    host: "127.0.0.1",
    port: 7332,
  };
}

function procLine(address: string, port: number, state = "0A"): string {
  return `  0: ${address}:${port.toString(16).padStart(4, "0")} 00000000:0000 ${state} 00000000:00000000 00:00000000 00000000 0 0 0`;
}

describe("local MCP service supervisor", () => {
  it("builds a shell-free detached start plan", () => {
    expect(buildLocalMcpServiceStartPlan(fixture())).toEqual({
      command: "/opt/example/bin/example-mcp",
      args: ["--transport", "http"],
      cwd: "/var/lib/example-mcp",
      pidFile: "/var/run/example-mcp/service.pid",
      logFile: "/var/log/example-mcp/service.log",
      detached: true,
    });
  });

  it("rejects non-loopback listeners and relative executables", () => {
    expect(() => validateLocalMcpServiceSpec({ ...fixture(), host: "0.0.0.0" })).toThrow(
      /loopback/,
    );
    expect(() => validateLocalMcpServiceSpec({ ...fixture(), command: "example-mcp" })).toThrow(
      /absolute path/,
    );
    expect(() => validateLocalMcpServiceSpec({ ...fixture(), args: ["--env-file=.env"] })).toThrow(
      /must not load .env/,
    );
  });

  it("accepts strict PID files and rejects ambiguous values", () => {
    expect(parsePidFile("4242\n")).toBe(4242);
    expect(() => parsePidFile("4242 trailing")).toThrow(/one positive/);
    expect(() => parsePidFile("1")).toThrow(/controllable/);
  });

  it("matches the exact process executable and supervised argument prefix", () => {
    const plan = buildLocalMcpServiceStartPlan(fixture());
    expect(() =>
      assertProcessIdentity("/opt/example/bin/example-mcp\0--transport\0http\0", plan),
    ).not.toThrow();
    expect(() => assertProcessIdentity("/bin/sh\0-c\0example-mcp\0", plan)).toThrow(/executable/);
    expect(() =>
      assertProcessIdentity("/opt/example/bin/example-mcp\0--transport\0http\0--extra\0", plan),
    ).toThrow(/argument count/);
    expect(() =>
      assertProcessIdentity("/opt/example/bin/example-mcp\0--transport\0 http \0", plan),
    ).toThrow(/arguments do not match/);
  });

  it("accepts loopback-only proc listeners", () => {
    const listeners = assertOnlyLoopbackListeners({
      port: 7332,
      tcp4: `sl local_address rem_address st\n${procLine("0100007F", 7332)}`,
      tcp6: "sl local_address rem_address st\n",
    });
    expect(listeners).toHaveLength(1);
    expect(listeners[0]?.loopback).toBe(true);
  });

  it("fails closed when the same port is exposed publicly", () => {
    expect(() =>
      assertOnlyLoopbackListeners({
        port: 7332,
        tcp4: `sl local_address rem_address st\n${procLine("00000000", 7332)}`,
        tcp6: "sl local_address rem_address st\n",
      }),
    ).toThrow(/non-loopback/);
  });

  it("probes a bounded loopback health endpoint without following redirects", async () => {
    const fetchImpl = vi.fn(async () => new Response(null, { status: 204 }));
    await expect(
      probeLocalMcpHealth(fixture(), {
        path: "/ready",
        timeoutMs: 500,
        fetchImpl,
      }),
    ).resolves.toEqual({
      ok: true,
      status: 204,
      url: "http://127.0.0.1:7332/ready",
    });
    expect(fetchImpl).toHaveBeenCalledWith(
      "http://127.0.0.1:7332/ready",
      expect.objectContaining({ method: "GET", redirect: "manual" }),
    );
  });

  it("fails closed on unhealthy responses and unsafe health paths", async () => {
    await expect(
      probeLocalMcpHealth(fixture(), {
        fetchImpl: async () => new Response(null, { status: 503 }),
      }),
    ).rejects.toThrow(/HTTP 503/);
    await expect(
      probeLocalMcpHealth(fixture(), { path: "https://example.test/health" }),
    ).rejects.toThrow(/absolute URL path/);
  });

  it("redacts common credential-bearing log fields", () => {
    const input =
      "Authorization: Bearer abc.def client_secret=synthetic-secret api_key:synthetic-key";
    const redacted = redactServiceLogLine(input);
    expect(redacted).not.toContain("abc.def");
    expect(redacted).not.toContain("synthetic-secret");
    expect(redacted).not.toContain("synthetic-key");
    expect(redacted).toContain("[redacted]");
  });
});
