// Runtime gateway RPC helper shared by CLI commands that call the Gateway.
import {
  GATEWAY_CLIENT_MODES,
  GATEWAY_CLIENT_NAMES,
} from "../../packages/gateway-protocol/src/client-info.js";
import {
  validateGatewayWorkerNamespaceGetResult,
  type GatewayWorkerNamespaceGetResult,
} from "../../packages/gateway-protocol/src/index.js";
import type { HelloOk } from "../../packages/gateway-protocol/src/schema/frames.js";
import type { OpenClawConfig } from "../config/types.openclaw.js";
import { callGateway, isImplicitLocalGatewayTarget } from "../gateway/call.js";
import { assertGatewayCliMessageContext } from "../gateway/operator-cli-message-input.js";
import { resolveGatewayLocalPortOverride } from "./gateway-port-option.js";
import type { GatewayRpcOpts } from "./gateway-rpc.types.js";
import { parseTimeoutMsWithFallback } from "./parse-timeout.js";
import { withProgress } from "./progress.js";

type CallGatewayFromCliRuntimeExtra = {
  clientName?: Parameters<typeof callGateway>[0]["clientName"];
  mode?: Parameters<typeof callGateway>[0]["mode"];
  deviceIdentity?: Parameters<typeof callGateway>[0]["deviceIdentity"];
  signal?: Parameters<typeof callGateway>[0]["signal"];
  expectFinal?: boolean;
  progress?: boolean;
  scopes?: Parameters<typeof callGateway>[0]["scopes"];
  defaultTimeoutMs?: number;
  timeoutMs?: number | null;
  label?: string;
  useStoredDeviceAuth?: boolean;
  requiredStoredDeviceAuthScopes?: Parameters<
    typeof callGateway
  >[0]["requiredStoredDeviceAuthScopes"];
  requireLocalBackendSharedAuth?: boolean;
  sharedStateMode?: Parameters<typeof callGateway>[0]["sharedStateMode"];
};

type GatewayCliTransportRpcOpts = Omit<GatewayRpcOpts, "timeout"> & {
  config?: OpenClawConfig;
  timeout?: string | null;
  localPortOverride?: number;
};

const DEFAULT_GATEWAY_RPC_TIMEOUT_MS = 30_000;

type VerifiedReadAuthMethod = "token" | "password" | "device-token" | "tailscale" | "trusted-proxy";

export type GatewayVerifiedReadConnection = Readonly<{
  bootId: string;
  connId: string;
  authMethod: VerifiedReadAuthMethod;
  role: "operator";
  scopes: readonly string[];
}>;

function isVerifiedReadAuthMethod(
  method: HelloOk["auth"]["method"],
): method is VerifiedReadAuthMethod {
  return (
    method === "token" ||
    method === "password" ||
    method === "device-token" ||
    method === "tailscale" ||
    method === "trusted-proxy"
  );
}

/** One authenticated, read-scoped RPC on the exact selected Gateway connection. */
export async function callGatewayVerifiedRead(
  opts: GatewayCliTransportRpcOpts & {
    expectedBootId: string;
    expectUrl: string;
    signal?: AbortSignal;
  },
): Promise<{
  kind: "gateway-verified-read";
  method: "gateway.workerNamespace.get";
  connection: GatewayVerifiedReadConnection;
  result: GatewayWorkerNamespaceGetResult;
}> {
  const method = "gateway.workerNamespace.get" as const;
  const params = {};
  if (
    !opts.expectedBootId ||
    opts.expectedBootId.length > 96 ||
    opts.expectedBootId.trim() !== opts.expectedBootId ||
    !opts.expectUrl
  ) {
    throw new Error("A selected Gateway URL and boot ID are required for a verified read");
  }
  assertGatewayCliMessageContext(method, params);
  let connection: GatewayVerifiedReadConnection | undefined;
  let helloError: Error | undefined;
  let helloCount = 0;
  const onHelloOk = (hello: HelloOk) => {
    // callGateway treats hello observers as best-effort. Preserve a validation
    // failure for its synchronous pre-send assertion instead of throwing here.
    helloCount += 1;
    if (helloCount !== 1) {
      helloError = new Error("Gateway connection changed before verified read dispatch");
      return;
    }
    const { bootId, connId } = hello.server;
    const { method: authMethod, role, scopes } = hello.auth;
    if (
      !bootId ||
      bootId !== opts.expectedBootId ||
      !connId ||
      role !== "operator" ||
      !Array.isArray(scopes) ||
      !scopes.includes("operator.read") ||
      !isVerifiedReadAuthMethod(authMethod)
    ) {
      helloError = new Error("Gateway verified-read admission changed or is unavailable");
      return;
    }
    connection = { bootId, connId, authMethod, role, scopes: [...scopes] };
  };
  const assertDispatchCurrent = () => {
    if (opts.signal?.aborted) {
      throw new Error("Gateway verified read was aborted before dispatch");
    }
    if (helloError) {
      throw helloError;
    }
    if (helloCount !== 1 || !connection || connection.bootId !== opts.expectedBootId) {
      throw new Error("Gateway verified-read connection is unavailable");
    }
  };
  const timeoutMs =
    opts.timeout === null
      ? null
      : parseTimeoutMsWithFallback(opts.timeout, DEFAULT_GATEWAY_RPC_TIMEOUT_MS, {
          invalidType: "error",
        });
  const result = await callGateway<unknown>({
    config: opts.config,
    url: opts.url,
    expectUrl: opts.expectUrl,
    token: opts.token,
    password: opts.password,
    method,
    params,
    clientName: GATEWAY_CLIENT_NAMES.CLI,
    mode: GATEWAY_CLIENT_MODES.CLI,
    scopes: ["operator.read"],
    requiredMethods: [method],
    allowLocalBackendAuthNone: false,
    sharedStateMode: "read-only",
    signal: opts.signal,
    timeoutMs,
    localPortOverride: resolveGatewayLocalPortOverride(opts),
    onHelloOk,
    assertDispatchCurrent,
  });
  assertDispatchCurrent();
  const admittedConnection = (): GatewayVerifiedReadConnection => {
    if (!connection) {
      throw new Error("Gateway verified-read connection is unavailable");
    }
    return connection;
  };
  const admitted = admittedConnection();
  if (!validateGatewayWorkerNamespaceGetResult(result) || result.bootId !== admitted.bootId) {
    throw new Error("Gateway verified-read response does not match the admitted connection");
  }
  return { kind: "gateway-verified-read", method, connection: admitted, result };
}

export async function isImplicitLocalGatewayTargetFromCliRuntime(
  opts: GatewayCliTransportRpcOpts,
): Promise<boolean> {
  return await isImplicitLocalGatewayTarget({
    config: opts.config,
    url: opts.url,
    localPortOverride: resolveGatewayLocalPortOverride(opts),
  });
}

export async function callGatewayFromCliRuntime<T = Record<string, unknown>>(
  method: string,
  opts: GatewayCliTransportRpcOpts,
  params?: unknown,
  extra?: CallGatewayFromCliRuntimeExtra,
) {
  assertGatewayCliMessageContext(method, params);
  const localPortOverride = resolveGatewayLocalPortOverride(opts);
  // Progress is disabled for JSON output so stdout stays parseable.
  const showProgress = extra?.progress ?? opts.json !== true;
  const timeoutMs =
    extra?.timeoutMs !== undefined
      ? extra.timeoutMs
      : opts.timeout === null
        ? null
        : parseTimeoutMsWithFallback(
            opts.timeout,
            extra?.defaultTimeoutMs ?? DEFAULT_GATEWAY_RPC_TIMEOUT_MS,
            { invalidType: "error" },
          );
  return await withProgress(
    {
      label: extra?.label ?? `Gateway ${method}`,
      indeterminate: true,
      enabled: showProgress,
    },
    async () =>
      await callGateway<T>({
        config: opts.config,
        url: opts.url,
        expectUrl: opts.expectUrl,
        token: opts.token,
        password: opts.password,
        method,
        params,
        deviceIdentity: extra?.deviceIdentity,
        expectFinal: extra?.expectFinal ?? Boolean(opts.expectFinal),
        scopes: extra?.scopes,
        useStoredDeviceAuth: extra?.useStoredDeviceAuth,
        requiredStoredDeviceAuthScopes: extra?.requiredStoredDeviceAuthScopes,
        requireLocalBackendSharedAuth: extra?.requireLocalBackendSharedAuth,
        allowLocalBackendAuthNone: extra?.clientName === undefined && extra?.mode === undefined,
        sharedStateMode: extra?.sharedStateMode,
        signal: extra?.signal,
        timeoutMs,
        localPortOverride,
        clientName: extra?.clientName ?? GATEWAY_CLIENT_NAMES.CLI,
        mode: extra?.mode ?? GATEWAY_CLIENT_MODES.CLI,
      }),
  );
}
