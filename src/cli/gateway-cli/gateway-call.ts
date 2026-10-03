import type { Command } from "commander";
import {
  callGatewayVerifiedReadFromCli,
  resolveGatewayRpcOptionsWithLocalPort,
  type GatewayRpcOpts,
} from "../gateway-rpc.js";

const SETUP_INFERENCE_DETECT_RPC_TIMEOUT_MS = 40_000;

function parseGatewayCallParams(value: string): unknown {
  try {
    const params: unknown = JSON.parse(value);
    return params;
  } catch {
    throw new Error("--params must be valid JSON.");
  }
}

export async function runGatewayCallCommand(params: {
  method: string;
  opts: GatewayRpcOpts & { params?: string; verifiedRead?: string };
  command: Command;
  callReadOnly: (method: string, opts: GatewayRpcOpts, params?: unknown) => Promise<unknown>;
}): Promise<{ result: unknown; verifiedRead: boolean; json: boolean }> {
  const { method, opts, command } = params;
  // Setup detection owns a 30s worker deadline; leave grace for the typed outcome.
  const callOpts =
    method === "openclaw.setup.detect" && command.getOptionValueSource("timeout") === "default"
      ? { ...opts, timeout: String(SETUP_INFERENCE_DETECT_RPC_TIMEOUT_MS) }
      : opts;
  const rpcOpts = resolveGatewayRpcOptionsWithLocalPort(callOpts, command);
  const callParams = parseGatewayCallParams(opts.params ?? "{}");
  const bootId = opts.verifiedRead;
  if (method === "gateway.workerNamespace.get" && bootId === undefined) {
    throw new Error(
      "gateway.workerNamespace.get requires --verified-read <boot-id> and --expect-url <url>.",
    );
  }
  if (bootId !== undefined && method !== "gateway.workerNamespace.get") {
    throw new Error("--verified-read is only available for gateway.workerNamespace.get.");
  }
  if (bootId === undefined) {
    return {
      result: await params.callReadOnly(method, rpcOpts, callParams),
      verifiedRead: false,
      json: rpcOpts.json === true,
    };
  }
  const expectUrl = rpcOpts.expectUrl;
  if (!expectUrl) {
    throw new Error("--verified-read requires --expect-url <url>.");
  }
  if (
    typeof callParams !== "object" ||
    callParams === null ||
    Array.isArray(callParams) ||
    Object.keys(callParams).length !== 0
  ) {
    throw new Error("gateway.workerNamespace.get accepts only empty params ({}).");
  }
  return {
    result: await callGatewayVerifiedReadFromCli({
      ...rpcOpts,
      expectedBootId: bootId,
      expectUrl,
    }),
    verifiedRead: true,
    json: rpcOpts.json === true,
  };
}
