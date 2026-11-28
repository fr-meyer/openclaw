// Gateway RPC-call parsing, read-only local-state transport, and verified connection admission.
import type { HelloOk } from "../../../packages/gateway-protocol/src/schema/frames.js";
import { callGatewayFromCliWithTransport } from "../gateway-rpc.js";

type GatewayRpcOpts = Parameters<typeof callGatewayFromCliWithTransport>[1];

export const DEFAULT_GATEWAY_RPC_TIMEOUT_MS = 10_000;

export async function callGatewayReadOnlyCli(
  method: string,
  opts: GatewayRpcOpts,
  params?: unknown,
) {
  return await callGatewayFromCliWithTransport(method, opts, params, {
    defaultTimeoutMs: DEFAULT_GATEWAY_RPC_TIMEOUT_MS,
    sharedStateMode: "read-only",
  });
}

export function parseGatewayCallParams(value = "{}"): unknown {
  try {
    return JSON.parse(value) as unknown;
  } catch {
    throw new Error("--params must be valid JSON.");
  }
}
type VerifiedAuthMethod = "token" | "password" | "device-token" | "tailscale" | "trusted-proxy";

function isVerifiedAuthMethod(method: unknown): method is VerifiedAuthMethod {
  return (
    method === "token" ||
    method === "password" ||
    method === "device-token" ||
    method === "tailscale" ||
    method === "trusted-proxy"
  );
}

function isBoundedIdentity(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= 96 &&
    value.trim() === value &&
    Array.from(value).every((character) => {
      const code = character.charCodeAt(0);
      return code > 0x1f && (code < 0x7f || code > 0x9f);
    })
  );
}

function captureConnection(hello: HelloOk, expectedBootId: string) {
  if (!Number.isSafeInteger(hello?.protocol) || hello.protocol < 1) {
    throw new Error("Verified read requires a valid Gateway protocol.");
  }
  if (!isBoundedIdentity(hello.server?.bootId) || !isBoundedIdentity(hello.server?.connId)) {
    throw new Error("Verified read requires bounded Gateway boot and connection identities.");
  }
  if (hello.server.bootId !== expectedBootId) {
    throw new Error("Verified read Gateway boot changed.");
  }
  if (!isVerifiedAuthMethod(hello.auth?.method)) {
    throw new Error("Verified read requires an approved authenticated Gateway method.");
  }
  if (
    hello.auth.role !== "operator" ||
    !Array.isArray(hello.auth.scopes) ||
    hello.auth.scopes.length !== 1 ||
    hello.auth.scopes[0] !== "operator.read"
  ) {
    throw new Error("Verified read requires exactly the operator.read socket grant.");
  }
  // Hello auth also carries issued bearer tokens. Copy only admitted evidence.
  return Object.freeze({
    protocol: hello.protocol,
    server: Object.freeze({ bootId: hello.server.bootId, connId: hello.server.connId }),
    auth: Object.freeze({
      method: hello.auth.method,
      role: hello.auth.role,
      scopes: Object.freeze([...hello.auth.scopes]),
    }),
    endpointMatch: true,
    bootMatch: true,
  });
}

export async function callGatewayVerifiedRead(
  method: string,
  opts: GatewayRpcOpts,
  params: unknown,
  expectedBootId: string,
) {
  if (!isBoundedIdentity(expectedBootId)) {
    throw new Error("--verified-read requires a bounded nonempty Gateway boot ID.");
  }
  if (
    typeof opts.expectUrl !== "string" ||
    !opts.expectUrl ||
    opts.expectUrl.trim() !== opts.expectUrl
  ) {
    throw new Error("--verified-read requires an explicit --expect-url.");
  }

  let current = true;
  let observed: ReturnType<typeof captureConnection> | undefined;
  let admitted: ReturnType<typeof captureConnection> | undefined;
  let observationError: Error | undefined;
  try {
    const result = await callGatewayFromCliWithTransport(method, opts, params, {
      defaultTimeoutMs: DEFAULT_GATEWAY_RPC_TIMEOUT_MS,
      sharedStateMode: "read-only",
      scopes: ["operator.read"],
      onHelloOk: (hello) => {
        if (!current || admitted) {
          return;
        }
        observed = undefined;
        try {
          observed = captureConnection(hello, expectedBootId);
          observationError = undefined;
        } catch (error) {
          observationError =
            error instanceof Error
              ? error
              : new Error("Verified read hello could not be captured.");
        }
      },
      // Hello observers are best effort; this owner guard must reject before ws.send.
      assertDispatchCurrent: () => {
        if (!current) {
          throw new Error("Verified read invocation is no longer current.");
        }
        if (admitted) {
          throw new Error("Verified read cannot repeat dispatch admission.");
        }
        if (observationError) {
          throw observationError;
        }
        if (!observed) {
          throw new Error("Verified read has no captured Gateway connection.");
        }
        admitted = observed;
      },
    });
    if (!admitted || observed !== admitted || observationError) {
      throw new Error("Verified read did not retain its exact dispatch admission.");
    }
    return Object.freeze({
      kind: "gateway-verified-read",
      method,
      connection: admitted,
      result,
    });
  } finally {
    current = false;
    observed = undefined;
  }
}
