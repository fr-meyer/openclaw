import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import type { HelloOk } from "../../packages/gateway-protocol/src/index.js";
import { runQaGatewayFixture } from "../../test/helpers/qa-gateway-cleanup.js";
import { createOpenClawTestState } from "../test-utils/openclaw-test-state.js";
import { getFreePort } from "../test-utils/ports.js";
import { resolveLeastPrivilegeOperatorScopesForMethod } from "./method-scopes.js";
import { dispatchGatewayRequestInProcessRaw } from "./server-in-process-dispatch.js";
import * as kernelFactory from "./server-kernel.js";
import type { GatewayClient, GatewayRequestContext } from "./server-methods/types.js";
import { createSyntheticPluginRuntimeClient } from "./server-plugin-runtime-client.js";
import { startGatewayServer } from "./server.js";
import { connectGatewayClient, disconnectGatewayClient } from "./test-helpers.e2e.js";

const identity = vi.hoisted(() => ({
  read: vi.fn(async () => ({
    deviceId: "synthetic-worker-namespace-device",
    publicKeyPem: "synthetic-unused-public-key",
    privateKeyPem: "synthetic-unused-private-key",
  })),
}));
vi.mock("../infra/device-identity-async.js", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../infra/device-identity-async.js")>()),
  loadOrCreateProcessDeviceIdentityAsync: identity.read,
}));

const METHOD = "gateway.workerNamespace.get";
// The public namespace format is stable across Gateway boots for this fixture identity.
const NAMESPACE = "gateway-a0b59bfbf518bb2703a1d6edb49ab9cf";
type Association = { bootId: string; namespace: string };

describe("Gateway worker namespace readback", { concurrent: false }, () => {
  let state: Awaited<ReturnType<typeof createOpenClawTestState>> | undefined;
  let server: Awaited<ReturnType<typeof startGatewayServer>> | undefined;
  let client: Awaited<ReturnType<typeof connectGatewayClient>> | undefined;
  let kernel: Awaited<ReturnType<typeof kernelFactory.createGatewayKernel>>;
  let hello: HelloOk;
  let port: number;
  const token = "synthetic-worker-namespace-token";

  beforeAll(async () => {
    state = await createOpenClawTestState({
      label: "gateway-worker-namespace-readback",
      layout: "home",
      env: {
        OPENCLAW_GATEWAY_PASSWORD: undefined,
        OPENCLAW_GATEWAY_TOKEN: undefined,
        OPENCLAW_SKIP_BROWSER_CONTROL_SERVER: "1",
        OPENCLAW_SKIP_CANVAS_HOST: "1",
        OPENCLAW_SKIP_CHANNELS: "1",
        OPENCLAW_SKIP_CRON: "1",
        OPENCLAW_SKIP_GMAIL_WATCHER: "1",
        OPENCLAW_SKIP_PROVIDERS: "1",
        OPENCLAW_DISABLE_BUNDLED_PLUGINS: "1",
        OPENCLAW_TEST_MINIMAL_GATEWAY: "0",
        VITEST: "1",
      },
    });
    port = await getFreePort();
    await state.writeConfig({
      gateway: { auth: { mode: "token", token }, port, controlUi: { enabled: false } },
      agents: { defaults: { utilityModel: "" } },
      plugins: { slots: { memory: "none" } },
    });
    state.applyEnv();
    const createKernel = kernelFactory.createGatewayKernel;
    const capture = vi
      .spyOn(kernelFactory, "createGatewayKernel")
      .mockImplementation(async (...args) => {
        kernel = await createKernel(...args);
        return kernel;
      });
    try {
      server = await startGatewayServer(port, {
        bind: "loopback",
        auth: { mode: "token", token },
        bootId: "synthetic-worker-boot-a",
        controlUiEnabled: false,
        sidecarStartup: "defer",
      });
      kernel.kernel.setDispatchReady(true);
      client = await connectGatewayClient({
        url: `ws://127.0.0.1:${port}`,
        token,
        scopes: ["operator.read"],
        onHelloOk: (observed) => {
          hello = observed;
        },
      });
    } finally {
      capture.mockRestore();
    }
  });

  afterAll(async () => {
    await runQaGatewayFixture(
      async () => {},
      async () => {
        if (client) {
          await disconnectGatewayClient(client);
        }
      },
      async () => {
        await server?.close({ reason: "worker namespace fixture complete" });
      },
      async () => {
        await state?.cleanup();
      },
    );
  });

  function requiredClient() {
    if (!client) {
      throw new Error("Gateway fixture client unavailable");
    }
    return client;
  }

  function admittedClient(method: GatewayClient["authenticationMethod"] = "token"): GatewayClient {
    return {
      ...createSyntheticPluginRuntimeClient({ scopes: ["operator.read"] }),
      authenticationMethod: method,
      connectionSignal: new AbortController().signal,
    };
  }

  async function dispatch(
    requester: GatewayClient | null,
    params: unknown = {},
    context = kernel.gatewayRequestContext,
  ) {
    return await dispatchGatewayRequestInProcessRaw(METHOD, params, {
      client: requester,
      context,
      methodRegistry: kernel.getAttachedGatewayMethodRegistry(),
    });
  }

  it("keeps ordinary authenticated diagnostics available", async () => {
    await expect(requiredClient().request("health", {})).resolves.toBeDefined();
    expect(hello.auth.method).toBe("token");
  });

  it("returns the existing startup namespace with the same authenticated hello boot", async () => {
    const readsBefore = identity.read.mock.calls.length;
    const result = await requiredClient().request<Association>(METHOD, {});
    expect(result).toEqual({ bootId: hello.server.bootId, namespace: NAMESPACE });
    expect(result.bootId).toBe("synthetic-worker-boot-a");
    expect(resolveLeastPrivilegeOperatorScopesForMethod(METHOD)).toEqual(["operator.read"]);
    await expect(requiredClient().request<Association>(METHOD, {})).resolves.toEqual(result);
    expect(identity.read).toHaveBeenCalledTimes(readsBefore);
  });

  it.each(["none", "bootstrap-token", undefined, "unknown"] as const)(
    "rejects unapproved or absent admitted authentication (%s), despite caller credential JSON",
    async (method) => {
      const requester = {
        ...admittedClient(),
        authenticationMethod: method as GatewayClient["authenticationMethod"],
      };
      requester.connect.auth = { token };
      const result = await dispatch(requester);
      expect(result).toMatchObject({ ok: false, error: { code: "FORBIDDEN" } });
      expect(result.payload).toBeUndefined();
    },
  );

  it.each(["token", "password", "device-token", "tailscale", "trusted-proxy"] as const)(
    "accepts admitted operator read authentication (%s)",
    async (method) => {
      const requester = admittedClient(method);
      await expect(dispatch(requester)).resolves.toMatchObject({
        ok: true,
        payload: { bootId: "synthetic-worker-boot-a", namespace: NAMESPACE },
      });
    },
  );

  it("rejects missing read scope, node role, and pre-connect dispatch", async () => {
    const noRead = admittedClient();
    noRead.connect.scopes = [];
    expect((await dispatch(noRead)).ok).toBe(false);
    const node = admittedClient();
    node.connect.role = "node";
    expect((await dispatch(node)).ok).toBe(false);
    expect(await dispatch(null)).toMatchObject({ ok: false, error: { code: "FORBIDDEN" } });
  });

  it("rejects an admitted connection after its original transport retires", async () => {
    const requester = admittedClient();
    const connection = new AbortController();
    connection.abort();
    await expect(
      dispatch({ ...requester, connectionSignal: connection.signal }),
    ).resolves.toMatchObject({
      ok: false,
      error: { code: "UNAVAILABLE" },
    });
  });

  it("rejects caller namespace or lifecycle substitution through RPC params", async () => {
    await expect(
      requiredClient().request(METHOD, {
        bootId: "caller-boot",
        namespace: "caller-namespace",
      }),
    ).rejects.toMatchObject({ code: "INVALID_REQUEST" });
  });

  it("reports unavailable when the prepared worker namespace reader is absent", async () => {
    const context = { ...kernel.gatewayRequestContext, readWorkerRuntimeIdentity: undefined };
    await expect(dispatch(admittedClient(), {}, context)).resolves.toMatchObject({
      ok: false,
      error: { code: "UNAVAILABLE" },
    });
  });

  it("rejects an original context after the canonical resolver selects a replacement", async () => {
    const original = kernel.pluginGatewayContext.current;
    kernel.pluginGatewayContext.current = {} as GatewayRequestContext;
    try {
      await expect(dispatch(admittedClient())).resolves.toMatchObject({
        ok: false,
        error: { code: "UNAVAILABLE" },
      });
    } finally {
      kernel.pluginGatewayContext.current = original;
    }
  });

  it("retires the original reader while the next boot retains the stable namespace", async () => {
    const read = kernel.gatewayRequestContext.readWorkerRuntimeIdentity;
    if (!read) {
      throw new Error("Expected prepared association reader");
    }
    expect(read()).toEqual({ bootId: "synthetic-worker-boot-a", namespace: NAMESPACE });
    await kernel.beginClosePrelude();
    expect(() => read()).toThrow("Gateway worker runtime identity is unavailable");
    await disconnectGatewayClient(requiredClient());
    await server?.close({ reason: "replace worker namespace fixture boot" });
    server = await startGatewayServer(port, {
      bind: "loopback",
      auth: { mode: "token", token },
      bootId: "synthetic-worker-boot-b",
      controlUiEnabled: false,
      sidecarStartup: "defer",
    });
    client = await connectGatewayClient({
      url: `ws://127.0.0.1:${port}`,
      token,
      scopes: ["operator.read"],
      onHelloOk: (observed) => {
        hello = observed;
      },
    });
    await expect(requiredClient().request<Association>(METHOD, {})).resolves.toEqual({
      bootId: hello.server.bootId,
      namespace: NAMESPACE,
    });
    expect(hello.server.bootId).toBe("synthetic-worker-boot-b");
    expect(() => read()).toThrow("Gateway worker runtime identity is unavailable");
  });
});
