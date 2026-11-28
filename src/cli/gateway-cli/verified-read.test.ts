// Exercises Commander -> CLI transport -> the real Gateway call owner; only
// native configuration, presentation and the low-level network client are synthetic.
import { Command } from "commander";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { HelloOk } from "../../../packages/gateway-protocol/src/schema/frames.js";
import { PROTOCOL_VERSION } from "../../../packages/gateway-protocol/src/version.js";
import { createDeferred } from "../../../test/helpers/promise.js";
import type { OpenClawConfig } from "../../config/types.openclaw.js";
import type { CallGatewayOptions } from "../../gateway/call.js";
import type { GatewayClientOptions } from "../../gateway/client.js";
import { withEnvAsync } from "../../test-utils/env.js";
import { registerGatewayCli } from "./register.js";

const fixture = vi.hoisted(() => ({
  config: {} as OpenClawConfig,
  hello: undefined as unknown,
  clientOptions: undefined as GatewayClientOptions | undefined,
  callOptions: undefined as CallGatewayOptions | undefined,
  stopWait: undefined as Promise<void> | undefined,
  request: vi.fn<(_method: string, _params: unknown) => Promise<unknown>>(async () => ({
    card: { id: "card-1" },
    attempts: [],
  })),
  stopped: vi.fn(),
  runtime: { log: vi.fn(), error: vi.fn(), writeJson: vi.fn(), exit: vi.fn() },
}));

vi.mock("../../runtime.js", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../../runtime.js")>()),
  defaultRuntime: fixture.runtime,
}));
vi.mock("../daemon-cli/register-service-commands.js", () => ({
  addGatewayServiceCommands: () => {},
}));
vi.mock("./run-command.js", () => ({ addGatewayRunCommand: (command: Command) => command }));
vi.mock("./register-restart-handoff.js", () => ({ addGatewayRestartHandoffCommands: () => {} }));
vi.mock("../../config/gateway-dispatch-config.js", () => ({
  readGatewayDispatchConfig: () => fixture.config,
  readGatewayDispatchConfigWithShellEnvFallback: async () => fixture.config,
}));
vi.mock("../../config/runtime-snapshot.js", () => ({
  getRuntimeConfigSnapshot: () => fixture.config,
}));
vi.mock("../../infra/device-identity.js", () => ({
  loadDeviceIdentityIfPresent: () => null,
}));
vi.mock("../../../packages/gateway-client/src/event-loop-ready.js", () => ({
  waitForEventLoopReady: async () => ({
    ready: true,
    elapsedMs: 0,
    maxDriftMs: 0,
    checks: 2,
    aborted: false,
  }),
}));
vi.mock("../../gateway/client.js", () => ({
  isGatewayConnectAssemblyError: () => false,
  prepareGatewayClientDeviceAuth: async () => {},
  GatewayClient: class {
    constructor(options: GatewayClientOptions) {
      fixture.clientOptions = options;
    }
    start() {
      // Copy synthetic decoded replies, including malformed replies, at the client boundary.
      fixture.clientOptions?.onHelloOk?.(structuredClone(fixture.hello) as HelloOk);
    }
    request(method: string, params: unknown) {
      return fixture.request(method, params);
    }
    stop() {}
    async stopAndWait() {
      fixture.stopped();
      await fixture.stopWait;
    }
  },
}));
vi.mock("../../gateway/call.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../gateway/call.js")>();
  return {
    ...actual,
    // Record the real owner's input without substituting admission or request behavior.
    callGateway: (options: CallGatewayOptions) => {
      fixture.callOptions = options;
      return actual.callGateway(options);
    },
  };
});

function hello(): HelloOk {
  return {
    type: "hello-ok",
    protocol: PROTOCOL_VERSION,
    server: { version: "fixture", bootId: "boot-1", connId: "connection-1" },
    features: { methods: ["workboard.cards.runs"], events: [] },
    snapshot: { presence: [], health: {}, stateVersion: { presence: 0, health: 0 }, uptimeMs: 0 },
    auth: {
      method: "token",
      role: "operator",
      scopes: ["operator.read"],
      deviceToken: "fixture-secret-token",
    },
    policy: { maxPayload: 1, maxBufferedBytes: 1, tickIntervalMs: 1 },
  };
}

async function invoke(
  extra = ["--verified-read", "boot-1", "--expect-url", "ws://127.0.0.1:18789"],
) {
  const program = new Command().exitOverride();
  program.configureOutput({ writeErr: () => {} });
  registerGatewayCli(program);
  await withEnvAsync(
    {
      OPENCLAW_GATEWAY_URL: undefined,
      OPENCLAW_GATEWAY_TOKEN: undefined,
      OPENCLAW_GATEWAY_PASSWORD: undefined,
      OPENCLAW_GATEWAY_PORT: undefined,
    },
    async () => {
      await program.parseAsync(
        [
          "gateway",
          "call",
          "workboard.cards.runs",
          "--json",
          "--params",
          '{"id":"card-1"}',
          ...extra,
        ],
        { from: "user" },
      );
    },
  );
}

describe("gateway call verified read", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    fixture.config = {
      gateway: {
        mode: "local",
        port: 18789,
        auth: { mode: "token", token: "fixture-native-token" },
      },
    };
    fixture.hello = hello();
    fixture.clientOptions = undefined;
    fixture.callOptions = undefined;
    fixture.stopWait = undefined;
  });

  it("returns same-connection proof using configured native credentials and a narrow read grant", async () => {
    await invoke();
    expect(fixture.runtime.exit).not.toHaveBeenCalled();
    expect(fixture.request).toHaveBeenCalledExactlyOnceWith("workboard.cards.runs", {
      id: "card-1",
    });
    expect(fixture.clientOptions).toMatchObject({
      token: "fixture-native-token",
      scopes: ["operator.read"],
      sharedStateMode: "read-only",
    });
    expect(fixture.callOptions?.useStoredDeviceAuth).toBeUndefined();
    expect(fixture.runtime.writeJson).toHaveBeenCalledExactlyOnceWith({
      kind: "gateway-verified-read",
      method: "workboard.cards.runs",
      connection: {
        protocol: PROTOCOL_VERSION,
        server: { bootId: "boot-1", connId: "connection-1" },
        auth: { method: "token", role: "operator", scopes: ["operator.read"] },
        endpointMatch: true,
        bootMatch: true,
      },
      result: { card: { id: "card-1" }, attempts: [] },
    });
    expect(JSON.stringify(fixture.runtime.writeJson.mock.calls)).not.toContain(
      "fixture-secret-token",
    );
    expect(fixture.stopped).toHaveBeenCalledOnce();
  });

  it.each(["password", "device-token", "tailscale", "trusted-proxy"] as const)(
    "accepts the approved %s method without replacing native credential selection",
    async (method) => {
      const observed = hello();
      observed.auth.method = method;
      fixture.hello = observed;
      fixture.config = {
        gateway: {
          mode: "local",
          port: 18789,
          auth: { mode: "password", password: "fixture-native-password" },
        },
      };
      await invoke();
      expect(fixture.clientOptions?.password).toBe("fixture-native-password");
      expect(fixture.request).toHaveBeenCalledOnce();
      expect(fixture.runtime.exit).not.toHaveBeenCalled();
    },
  );

  it.each([
    ["none", { ...hello(), auth: { ...hello().auth, method: "none" } }],
    [
      "missing authentication method",
      { ...hello(), auth: { role: "operator", scopes: ["operator.read"] } },
    ],
    [
      "unknown authentication method",
      { ...hello(), auth: { ...hello().auth, method: "future-method" } },
    ],
    [
      "bootstrap authentication",
      { ...hello(), auth: { ...hello().auth, method: "bootstrap-token" } },
    ],
    ["wrong role", { ...hello(), auth: { ...hello().auth, role: "node" } }],
    ["insufficient scopes", { ...hello(), auth: { ...hello().auth, scopes: [] } }],
    [
      "overbroad scopes",
      { ...hello(), auth: { ...hello().auth, scopes: ["operator.read", "operator.admin"] } },
    ],
    [
      "duplicate scopes",
      { ...hello(), auth: { ...hello().auth, scopes: ["operator.read", "operator.read"] } },
    ],
    ["missing boot", { ...hello(), server: { connId: "connection-1" } }],
    ["wrong boot", { ...hello(), server: { bootId: "boot-2", connId: "connection-1" } }],
    ["unbounded boot", { ...hello(), server: { bootId: "b".repeat(97), connId: "connection-1" } }],
    ["empty connection", { ...hello(), server: { bootId: "boot-1", connId: "" } }],
    ["unbounded connection", { ...hello(), server: { bootId: "boot-1", connId: "c".repeat(97) } }],
    ["missing auth", { ...hello(), auth: undefined }],
  ])("rejects %s before any RPC and closes the current client", async (_name, observed) => {
    fixture.hello = observed;
    await invoke();
    expect(fixture.request).not.toHaveBeenCalled();
    expect(fixture.stopped).toHaveBeenCalledOnce();
    expect(fixture.runtime.exit).toHaveBeenCalledExactlyOnceWith(1);
    expect(fixture.runtime.writeJson).toHaveBeenCalledWith(
      expect.objectContaining({ ok: false, error: expect.anything() }),
    );
    expect(JSON.stringify(fixture.runtime.writeJson.mock.calls)).not.toContain(
      "fixture-secret-token",
    );
  });

  it("rejects endpoint drift before constructing a network client", async () => {
    await invoke(["--verified-read", "boot-1", "--expect-url", "ws://127.0.0.1:19001"]);
    expect(fixture.clientOptions).toBeUndefined();
    expect(fixture.request).not.toHaveBeenCalled();
    expect(fixture.runtime.exit).toHaveBeenCalledExactlyOnceWith(1);
  });

  it.each([
    ["--verified-read", "boot-1"],
    ["--verified-read", "", "--expect-url", "ws://127.0.0.1:18789"],
  ])("requires explicit valid boot and endpoint before connection (%j)", async (...extra) => {
    await invoke(extra);
    expect(fixture.clientOptions).toBeUndefined();
    expect(fixture.runtime.exit).toHaveBeenCalledExactlyOnceWith(1);
  });

  it("joins client cleanup and retains proof from the admitted connection", async () => {
    const stopped = createDeferred();
    const cleanupStarted = createDeferred();
    fixture.stopWait = stopped.promise;
    fixture.stopped.mockImplementationOnce(() => cleanupStarted.resolve());
    const pending = invoke();
    await cleanupStarted.promise;
    expect(fixture.runtime.writeJson).not.toHaveBeenCalled();
    const duringCleanup = hello();
    duringCleanup.server.connId = "connection-2";
    fixture.clientOptions?.onHelloOk?.(duringCleanup);
    stopped.resolve();
    await pending;
    const envelope = fixture.runtime.writeJson.mock.calls[0]?.[0];
    expect(envelope).toMatchObject({
      kind: "gateway-verified-read",
      connection: { server: { connId: "connection-1" } },
    });
    expect(fixture.request).toHaveBeenCalledOnce();
  });

  it("rejects a second hello while the first admitted request is pending", async () => {
    const firstResult = createDeferred<unknown>();
    const firstRequest = createDeferred();
    fixture.request.mockImplementationOnce(async () => {
      firstRequest.resolve();
      return await firstResult.promise;
    });
    const pending = invoke();
    await firstRequest.promise;
    const replacement = hello();
    replacement.server.connId = "connection-2";
    fixture.clientOptions?.onHelloOk?.(replacement);
    await pending;
    expect(fixture.request).toHaveBeenCalledOnce();
    expect(fixture.stopped).toHaveBeenCalledOnce();
    expect(fixture.runtime.exit).toHaveBeenCalledExactlyOnceWith(1);
    expect(fixture.runtime.writeJson).toHaveBeenCalledExactlyOnceWith(
      expect.objectContaining({ ok: false }),
    );
    firstResult.resolve({ late: true });
    await fixture.request.mock.results[0]?.value;
    expect(fixture.runtime.writeJson).toHaveBeenCalledOnce();
  });

  it("preserves the ordinary non-opt-in method result", async () => {
    await invoke([]);
    expect(fixture.runtime.writeJson).toHaveBeenCalledExactlyOnceWith({
      card: { id: "card-1" },
      attempts: [],
    });
  });
});
