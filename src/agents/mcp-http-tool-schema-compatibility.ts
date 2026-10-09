import { createHash } from "node:crypto";
import type { JSONRPCMessage } from "@modelcontextprotocol/sdk/types.js";
import { isRecord } from "@openclaw/normalization-core/record-coerce";

const NOWISTAY_MCP_ENDPOINT = "https://api.nowistay.com/mcp";
// Fresh tools/list contract observed on 2026-10-05. A changed contract stays strict.
const NOWISTAY_LIST_PROPERTIES_SCHEMA_SHA256 =
  "dec273fd731992d5fe977c505e307feab862be078ad8c55079d364c8e58e8500";

function canonicalize(value: unknown, depth = 0): unknown {
  if (depth > 32) {
    throw new Error("MCP tool schema exceeds compatibility fingerprint depth");
  }
  if (Array.isArray(value)) {
    return value.map((entry) => canonicalize(entry, depth + 1));
  }
  if (isRecord(value)) {
    return Object.fromEntries(
      Object.keys(value)
        .toSorted()
        .map((key) => [key, canonicalize(value[key], depth + 1)]),
    );
  }
  return value;
}

function compatibleNowistayTool(tool: unknown): unknown {
  if (!isRecord(tool) || tool.name !== "list_properties" || !isRecord(tool.outputSchema)) {
    return tool;
  }
  const schema = tool.outputSchema;
  const properties = schema.properties;
  const items = isRecord(properties) ? properties.items : undefined;
  const item = isRecord(items) ? items.items : undefined;
  if (
    !isRecord(properties) ||
    !isRecord(items) ||
    !isRecord(item) ||
    !isRecord(item.properties) ||
    item.additionalProperties !== false ||
    Object.hasOwn(item.properties, "vatRate")
  ) {
    return tool;
  }
  try {
    const encoded = JSON.stringify(canonicalize(schema));
    if (encoded === undefined) {
      return tool;
    }
    const fingerprint = createHash("sha256").update(encoded).digest("hex");
    if (fingerprint !== NOWISTAY_LIST_PROPERTIES_SCHEMA_SHA256) {
      return tool;
    }
  } catch {
    // Leave unfamiliar or malformed schemas to the normal SDK validator.
    return tool;
  }
  return {
    ...tool,
    outputSchema: {
      ...schema,
      properties: {
        ...properties,
        items: {
          ...items,
          items: {
            ...item,
            properties: {
              ...item.properties,
              // The provider documents vat_rate as a 0–100 numeric percentage;
              // its property response also returns null when VAT is not applicable.
              vatRate: { type: ["number", "null"], minimum: 0, maximum: 100 },
            },
          },
        },
      },
    },
  };
}

/** Repairs one known remote metadata defect before SDK output validators cache it. */
export class McpHttpToolSchemaCompatibility {
  private readonly enabled: boolean;
  private readonly pendingToolLists = new Set<string | number>();

  constructor(url: URL) {
    this.enabled = url.href === NOWISTAY_MCP_ENDPOINT;
  }

  recordRequest(message: JSONRPCMessage): void {
    if (!this.enabled || !("method" in message)) {
      return;
    }
    if (message.method === "notifications/cancelled" && isRecord(message.params)) {
      const requestId = message.params.requestId;
      if (typeof requestId === "string" || typeof requestId === "number") {
        this.pendingToolLists.delete(requestId);
      }
      return;
    }
    if (
      message.method === "tools/list" &&
      "id" in message &&
      (typeof message.id === "string" || typeof message.id === "number")
    ) {
      this.pendingToolLists.add(message.id);
    }
  }

  forgetRequest(message: JSONRPCMessage): void {
    if ("id" in message && (typeof message.id === "string" || typeof message.id === "number")) {
      this.pendingToolLists.delete(message.id);
    }
  }

  normalizeResponse(message: JSONRPCMessage): JSONRPCMessage {
    if (
      !this.enabled ||
      "method" in message ||
      !("id" in message) ||
      (typeof message.id !== "string" && typeof message.id !== "number") ||
      !this.pendingToolLists.delete(message.id) ||
      !("result" in message) ||
      !Array.isArray(message.result.tools)
    ) {
      return message;
    }
    let changed = false;
    const tools = message.result.tools.map((tool) => {
      const normalized = compatibleNowistayTool(tool);
      changed ||= normalized !== tool;
      return normalized;
    });
    return changed ? { ...message, result: { ...message.result, tools } } : message;
  }

  clear(): void {
    this.pendingToolLists.clear();
  }
}
