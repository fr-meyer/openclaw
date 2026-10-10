import { describe, expect, it, vi } from "vitest";
import { systemHandlers } from "./system.js";
import type { GatewayClient, GatewayRequestOptions } from "./types.js";

const METHOD = "gateway.workerNamespace.get";
const namespace = "gateway-synthetic-prepared-namespace";

function admittedClient(): GatewayClient {
  return {
    connect: { role: "operator", scopes: ["operator.read"] },
    internal: { authenticatedOperator: true },
    authenticatedMethod: "token",
    connId: "synthetic-reader",
    gatewayBootId: "synthetic-boot-a",
    connectionSignal: new AbortController().signal,
  } as GatewayClient;
}

async function readNamespace(overrides: Partial<GatewayRequestOptions> = {}) {
  const respond = vi.fn();
  const options = {
    params: {},
    client: admittedClient(),
    context: { nodeWorkerGatewayNamespace: namespace },
    hasCurrentClientAuthority: () => true,
    signal: new AbortController().signal,
    ...overrides,
    respond,
  } as GatewayRequestOptions;
  await systemHandlers[METHOD]!(options);
  expect(respond).toHaveBeenCalledOnce();
  const [ok, payload, error] = respond.mock.calls[0]!;
  return { ok, payload, error };
}

describe("prepared Gateway worker namespace readback", () => {
  it.each(["token", "password", "device-token", "tailscale", "trusted-proxy"] as const)(
    "returns prepared identity for a current admitted %s reader",
    async (authenticatedMethod) => {
      const client = { ...admittedClient(), authenticatedMethod };
      await expect(readNamespace({ client })).resolves.toEqual({
        ok: true,
        payload: { bootId: "synthetic-boot-a", namespace },
        error: undefined,
      });
      client.gatewayBootId = "synthetic-boot-b";
      await expect(readNamespace({ client })).resolves.toMatchObject({
        ok: true,
        payload: { bootId: "synthetic-boot-b", namespace },
      });
    },
  );

  it.each(["none", "bootstrap-token", "unknown", undefined])(
    "rejects unapproved authentication %s even with credential JSON",
    async (method) => {
      const client = admittedClient();
      client.authenticatedMethod = method as GatewayClient["authenticatedMethod"];
      client.connect.auth = { token: "synthetic-caller-token" };
      await expect(readNamespace({ client })).resolves.toMatchObject({
        ok: false,
        payload: undefined,
        error: { code: "FORBIDDEN" },
      });
    },
  );

  it.each([
    "no read scope",
    "node role",
    "no attestation",
    "no connection",
    "no boot",
    "retired connection",
    "invalidated client",
    "retired request",
    "retired authority",
    "pre-connect",
  ] as const)("rejects %s without disclosing identity", async (reason) => {
    const client = admittedClient();
    const options: Partial<GatewayRequestOptions> = { client };
    const aborted = new AbortController();
    aborted.abort();
    if (reason === "no read scope") client.connect.scopes = [];
    if (reason === "node role") client.connect.role = "node";
    if (reason === "no attestation") client.internal = {};
    if (reason === "no connection") client.connId = "";
    if (reason === "no boot") client.gatewayBootId = undefined;
    if (reason === "retired connection") client.connectionSignal = aborted.signal;
    if (reason === "invalidated client") client.invalidated = true;
    if (reason === "retired request") options.signal = aborted.signal;
    if (reason === "retired authority") options.hasCurrentClientAuthority = () => false;
    if (reason === "pre-connect") options.client = null;
    await expect(readNamespace(options)).resolves.toMatchObject({
      ok: false,
      payload: undefined,
      error: { code: "FORBIDDEN" },
    });
  });

  it("rejects caller substitution and reports missing prepared namespace", async () => {
    await expect(
      readNamespace({ params: { bootId: "caller-boot", namespace: "caller-namespace" } }),
    ).resolves.toMatchObject({ ok: false, error: { code: "INVALID_REQUEST" } });
    await expect(
      readNamespace({ context: {} as GatewayRequestOptions["context"] }),
    ).resolves.toMatchObject({ ok: false, error: { code: "UNAVAILABLE" } });
  });
});
