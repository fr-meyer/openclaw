import type { Client } from "@modelcontextprotocol/sdk/client/index.js";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import { emitTrustedDiagnosticEvent } from "../infra/diagnostic-events.js";
import type {
  DiagnosticMcpLifecycleFields,
  DiagnosticMcpLifecyclePhase,
  DiagnosticMcpRetirementIntent,
} from "../infra/diagnostic-mcp-lifecycle.js";
import { OpenClawStdioClientTransport } from "./mcp-stdio-transport.js";
import type { McpToolCatalogMetadata } from "./mcp-tool-metadata.js";

export type BundleMcpSession = {
  generationId: string;
  closeOutcome: DiagnosticMcpLifecycleFields["closeOutcome"];
  serverName: string;
  client: Client;
  transport: Transport;
  transportType: "stdio" | "sse" | "streamable-http";
  requestTimeoutMs: number;
  connected: boolean;
  disconnectReason?: string;
  retiring: boolean;
  connectPromise?: Promise<void>;
  disposePromise?: Promise<void>;
  detachStderr?: () => void;
  toolMetadata?: McpToolCatalogMetadata;
};

/** Project owner facts without deciding admission, retirement, or cleanup. */
export function recordBundleMcpSession(
  session: BundleMcpSession,
  phase: DiagnosticMcpLifecyclePhase,
  facts: {
    activeLeases: number;
    retirementIntent: DiagnosticMcpRetirementIntent;
    catalogRetired: boolean;
  },
): void {
  try {
    const childPid =
      session.transport instanceof OpenClawStdioClientTransport
        ? session.transport.diagnosticPid
        : undefined;
    emitTrustedDiagnosticEvent({
      type: "mcp.lifecycle",
      phase,
      mcp: {
        generationId: session.generationId,
        providerClass: session.transportType,
        ...(childPid !== undefined ? { childPid } : {}),
        serverRuntimeActiveLeases: facts.activeLeases,
        retirementIntent: facts.retirementIntent,
        retiring: Boolean(facts.catalogRetired || session.retiring || session.disposePromise),
        connected: session.connected,
        closeOutcome: session.closeOutcome,
      },
    });
  } catch {
    // Best-effort diagnostics never change lease, admission, or cleanup outcomes.
  }
}
