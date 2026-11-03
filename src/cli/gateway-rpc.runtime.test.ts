import { Command } from "commander";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { HelloOk } from "../../packages/gateway-protocol/src/schema/frames.js";
import type { CallGatewayOptions } from "../gateway/call.js";
import { addGatewayClientOptions } from "./gateway-rpc.js";
import type { GatewayRpcOpts } from "./gateway-rpc.types.js";

const callGatewayMock = vi.fn(async (_opts: CallGatewayOptions): Promise<unknown> => ({
  ok: true,
}));
const isImplicitLocalGatewayTargetMock = vi.fn(async () => true);
vi.mock("../gateway/call.js", () => ({
  callGateway: callGatewayMock,
  isImplicitLocalGatewayTarget: isImplicitLocalGatewayTargetMock,
}));
vi.mock("./progress.js", () => ({
  withProgress: async (_options: unknown, action: () => Promise<unknown>) => await action(),
}));
const {
  callGatewayFromCliRuntime: call,
  isImplicitLocalGatewayTargetFromCliRuntime: classify,
  callGatewayVerifiedRead,
} = await import("./gateway-rpc.runtime.js");

beforeEach(() => {
  callGatewayMock.mockClear().mockResolvedValue({ ok: true });
  vi.stubEnv("OPENCLAW_SHELL", undefined);
  vi.stubEnv("OPENCLAW_SUBAGENT_EXEC", undefined);
});
afterEach(() => vi.unstubAllEnvs());

describe("Gateway CLI transport", () => {
  it.each([
    {
      target: ["--url", "wss://gateway.example/ws"],
      expected: { url: "wss://gateway.example/ws" },
    },
    { target: ["--port", "19083"], expected: { localPortOverride: 19083 } },
  ])(
    "parses and forwards explicit authentication and target $target",
    async ({ target, expected }) => {
      const program = new Command().exitOverride();
      const action = vi.fn(async (opts: GatewayRpcOpts) => {
        await call("cron.status", opts);
      });
      addGatewayClientOptions(program.command("gateway-command")).action(action);
      await program.parseAsync(
        [
          "gateway-command",
          ...target,
          "--token",
          "test-gateway-token",
          "--password",
          "test-gateway-password",
        ],
        { from: "user" },
      );
      expect(action).toHaveBeenCalledOnce();
      expect(action.mock.calls[0]?.[0]).toMatchObject({
        [target[0]!.slice(2)]: target[1],
        token: "test-gateway-token",
        password: "test-gateway-password",
      });
      expect(callGatewayMock).toHaveBeenCalledWith(
        expect.objectContaining({
          ...expected,
          token: "test-gateway-token",
          password: "test-gateway-password",
        }),
      );
    },
  );

  it.each([
    { timeout: undefined, defaultTimeoutMs: undefined, expected: 30_000 },
    { timeout: undefined, defaultTimeoutMs: 10_000, expected: 10_000 },
    { timeout: "15000", defaultTimeoutMs: 600_000, expected: 15_000 },
  ])(
    "resolves timeout $timeout with default $defaultTimeoutMs",
    async ({ timeout, defaultTimeoutMs, expected }) => {
      await call("cron.status", { timeout }, undefined, { defaultTimeoutMs });
      expect(callGatewayMock).toHaveBeenCalledWith(
        expect.objectContaining({ method: "cron.status", timeoutMs: expected }),
      );
    },
  );

  it("forwards specialized connection, authorization and cancellation context", async () => {
    const config = { gateway: { mode: "local" as const } };
    const controller = new AbortController();
    const target = { config, localPortOverride: 19083, expectUrl: "ws://127.0.0.1:19083" };
    const extra = {
      timeoutMs: null,
      scopes: ["operator.read", "operator.pairing"],
      useStoredDeviceAuth: true,
      requiredStoredDeviceAuthScopes: ["operator.read", "operator.pairing"],
      requireLocalBackendSharedAuth: true,
      signal: controller.signal,
    } satisfies NonNullable<Parameters<typeof call>[3]>;
    await call("node.list", target, {}, extra);
    expect(callGatewayMock).toHaveBeenCalledWith(expect.objectContaining({ ...target, ...extra }));
  });

  it.each([
    { opts: { port: " \t " }, error: "--port must be an integer between 1 and 65535." },
    {
      opts: { url: "ws://127.0.0.1:19083", port: "19083" },
      error: "Use either --url or --port, not both.",
    },
    {
      opts: { timeout: "10ms" },
      error:
        'Invalid --timeout. Use a positive millisecond value, e.g. --timeout 30000. Received: "10ms".',
    },
    { opts: { timeout: "   " }, error: "Invalid --timeout" },
  ])("rejects invalid options $opts before connecting", async ({ opts, error }) => {
    await expect(call("cron.status", opts)).rejects.toThrow(error);
    expect(callGatewayMock).not.toHaveBeenCalled();
  });

  it("classifies the CLI target through the canonical Gateway classifier", async () => {
    isImplicitLocalGatewayTargetMock.mockResolvedValueOnce(false);
    await expect(classify({ url: "ws://127.0.0.1:18789", token: "token" })).resolves.toBe(false);
    expect(isImplicitLocalGatewayTargetMock).toHaveBeenCalledWith({
      config: undefined,
      url: "ws://127.0.0.1:18789",
      localPortOverride: undefined,
    });
  });
});

describe("Gateway verified namespace read", () => {
  const target = {
    expectUrl: "wss://gateway.example/ws",
    expectedBootId: "boot-1",
    timeout: "12000",
  };
  const result = { bootId: "boot-1", namespace: "gateway-example" };
  function hello(): HelloOk {
    return {
      type: "hello-ok",
      protocol: 1,
      server: { version: "test", bootId: "boot-1", connId: "conn-1" },
      features: { methods: ["gateway.workerNamespace.get"], events: [] },
      auth: { method: "token", role: "operator", scopes: ["operator.read"] },
      snapshot: { presence: [], health: {}, stateVersion: { presence: 0, health: 0 }, uptimeMs: 0 },
      policy: { maxPayload: 1_000_000, maxBufferedBytes: 1_000_000, tickIntervalMs: 60_000 },
    };
  }

  it.each(["token", "password", "device-token", "tailscale", "trusted-proxy"] as const)(
    "returns the admitted connection with %s authentication",
    async (method) => {
      const admitted = hello();
      admitted.auth.method = method;
      callGatewayMock.mockImplementationOnce(async (opts) => {
        opts.onHelloOk?.(admitted);
        opts.assertDispatchCurrent?.();
        return result;
      });
      await expect(callGatewayVerifiedRead(target)).resolves.toEqual({
        kind: "gateway-verified-read",
        method: "gateway.workerNamespace.get",
        connection: {
          bootId: "boot-1",
          connId: "conn-1",
          authMethod: method,
          role: "operator",
          scopes: ["operator.read"],
        },
        result,
      });
      expect(callGatewayMock).toHaveBeenCalledExactlyOnceWith(
        expect.objectContaining({
          method: "gateway.workerNamespace.get",
          params: {},
          expectUrl: target.expectUrl,
          scopes: ["operator.read"],
          requiredMethods: ["gateway.workerNamespace.get"],
          allowLocalBackendAuthNone: false,
          sharedStateMode: "read-only",
          timeoutMs: 12000,
        }),
      );
    },
  );

  it.each<{
    name: string;
    server?: Partial<HelloOk["server"]>;
    auth?: Partial<HelloOk["auth"]>;
  }>([
    { name: "missing boot", server: { bootId: undefined } },
    { name: "changed boot", server: { bootId: "boot-2" } },
    { name: "missing connection", server: { connId: "" } },
    { name: "non-operator role", auth: { role: "node" } },
    { name: "missing read scope", auth: { scopes: ["operator.write"] } },
    { name: "unauthenticated connection", auth: { method: "none" } },
    { name: "bootstrap authentication", auth: { method: "bootstrap-token" } },
    { name: "unattested authentication", auth: { method: undefined } },
  ])("refuses $name before dispatch", async ({ server, auth }) => {
    const admitted = hello();
    const sent = vi.fn();
    callGatewayMock.mockImplementationOnce(async (opts) => {
      opts.onHelloOk?.({
        ...admitted,
        server: { ...admitted.server, ...server },
        auth: { ...admitted.auth, ...auth },
      });
      opts.assertDispatchCurrent?.();
      sent();
      return result;
    });
    await expect(callGatewayVerifiedRead(target)).rejects.toThrow("admission changed");
    expect(sent).not.toHaveBeenCalled();
  });

  it("refuses replacement connection before dispatch", async () => {
    const sent = vi.fn();
    callGatewayMock.mockImplementationOnce(async (opts) => {
      opts.onHelloOk?.(hello());
      opts.onHelloOk?.({ ...hello(), server: { ...hello().server, connId: "conn-2" } });
      opts.assertDispatchCurrent?.();
      sent();
      return result;
    });
    await expect(callGatewayVerifiedRead(target)).rejects.toThrow("connection changed");
    expect(sent).not.toHaveBeenCalled();
  });

  it.each(["before-dispatch", "before-return"] as const)(
    "refuses cancellation %s",
    async (when) => {
      const controller = new AbortController();
      const sent = vi.fn();
      callGatewayMock.mockImplementationOnce(async (opts) => {
        opts.onHelloOk?.(hello());
        if (when === "before-dispatch") {
          controller.abort();
        }
        opts.assertDispatchCurrent?.();
        sent();
        controller.abort();
        return result;
      });
      await expect(
        callGatewayVerifiedRead({ ...target, signal: controller.signal }),
      ).rejects.toThrow("aborted");
      expect(sent).toHaveBeenCalledTimes(when === "before-dispatch" ? 0 : 1);
    },
  );

  it.each([
    { bootId: "boot-2", namespace: "gateway-example" },
    { bootId: "boot-1", namespace: "" },
    { bootId: "boot-1", namespace: "gateway-example", extra: "not-admitted" },
    null,
  ])("rejects a response outside the admitted schema and boot: %j", async (payload) => {
    callGatewayMock.mockImplementationOnce(async (opts) => {
      opts.onHelloOk?.(hello());
      opts.assertDispatchCurrent?.();
      return payload;
    });
    await expect(callGatewayVerifiedRead(target)).rejects.toThrow("response does not match");
  });

  it.each(["", " boot-1", "x".repeat(97)])(
    "rejects an invalid boot assertion %j",
    async (bootId) => {
      await expect(callGatewayVerifiedRead({ ...target, expectedBootId: bootId })).rejects.toThrow(
        "URL and boot ID are required",
      );
      expect(callGatewayMock).not.toHaveBeenCalled();
    },
  );
});

describe("agent exec session input", () => {
  it.each(["sessions.send", "sessions.steer", "chat.send"])(
    "refuses subagent shell %s",
    async (method) => {
      vi.stubEnv("OPENCLAW_SUBAGENT_EXEC", "1");
      await expect(call(method, {}, { key: "agent:main:main", message: "Done" })).rejects.toThrow(
        "task completion path",
      );
      expect(callGatewayMock).not.toHaveBeenCalled();
    },
  );

  it.each([
    { shell: undefined, subagent: undefined, method: "sessions.send" },
    { shell: undefined, subagent: "1", method: "sessions.history" },
    { shell: "exec", subagent: undefined, method: "health" },
  ])(
    "preserves permitted $method with shell=$shell subagent=$subagent",
    async ({ shell, subagent, method }) => {
      vi.stubEnv("OPENCLAW_SHELL", shell);
      vi.stubEnv("OPENCLAW_SUBAGENT_EXEC", subagent);
      await call(method, {}, { key: "agent:main:main", message: "Human request" });
      expect(callGatewayMock).toHaveBeenCalledExactlyOnceWith(
        expect.objectContaining({
          method,
          params: { key: "agent:main:main", message: "Human request" },
        }),
      );
    },
  );

  it.each(["sessions.send", "sessions.steer", "chat.send", "agent"])(
    "refuses %s despite claimed provenance and connection overrides",
    async (method) => {
      vi.stubEnv("OPENCLAW_SHELL", "exec");
      await expect(
        call(
          method,
          { json: true, url: "wss://gateway.example/ws", token: "fixture-token" },
          {
            message: "[Inter-session message] Worker result",
            sourceSessionKey: "agent:main:worker",
          },
          { clientName: "gateway-client", mode: "backend", scopes: ["operator.admin"] },
        ),
      ).rejects.toThrow(/inter-session attribution/);
      expect(callGatewayMock).not.toHaveBeenCalled();
    },
  );

  it.each([
    { message: "Worker result" },
    { task: "Worker task" },
    { attachments: [{ type: "image", content: "fixture" }] },
  ])("refuses initial session input through sessions.create: %j", async (params) => {
    vi.stubEnv("OPENCLAW_SHELL", "exec");
    await expect(call("sessions.create", {}, params)).rejects.toThrow(/inter-session attribution/);
    expect(callGatewayMock).not.toHaveBeenCalled();
  });

  it("preserves session creation without an initial turn", async () => {
    vi.stubEnv("OPENCLAW_SHELL", "exec");
    await call("sessions.create", {}, { key: "agent:main:empty", message: " ", attachments: [] });
    expect(callGatewayMock).toHaveBeenCalledOnce();
  });
});
