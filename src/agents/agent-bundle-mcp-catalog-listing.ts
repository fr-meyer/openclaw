import type { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { ErrorCode, ListToolsResultSchema, type Tool } from "@modelcontextprotocol/sdk/types.js";
import { isRecord } from "@openclaw/normalization-core/record-coerce";
import { collectMcpPaginatedItems } from "./mcp-pagination.js";

export const BUNDLE_MCP_LIST_LIMITS = Object.freeze({
  pages: 128,
  items: 16_384,
  bytes: 10 * 1024 * 1024,
});

export async function listAllTools(
  client: Client,
  timeoutMs: number,
  signal: AbortSignal,
): Promise<Tool[]> {
  return await collectMcpPaginatedItems({
    label: "MCP tool listing",
    itemLabel: "tools",
    timeoutMs,
    maxPages: BUNDLE_MCP_LIST_LIMITS.pages,
    maxItems: BUNDLE_MCP_LIST_LIMITS.items,
    maxBytes: BUNDLE_MCP_LIST_LIMITS.bytes,
    signal,
    loadPage: async ({ cursor, requestTimeoutMs, signal: requestSignal }) => {
      const requestController = new AbortController();
      const onAbort = () => requestController.abort(requestSignal.reason);
      requestSignal.addEventListener("abort", onAbort, { once: true });
      if (requestSignal.aborted) {
        onAbort();
      }
      try {
        const page = await client.request(
          { method: "tools/list", params: cursor === undefined ? undefined : { cursor } },
          ListToolsResultSchema,
          {
            timeout: requestTimeoutMs,
            maxTotalTimeout: requestTimeoutMs,
            signal: requestController.signal,
          },
        );
        return { items: page.tools, nextCursor: page.nextCursor, serializedValue: page };
      } finally {
        requestSignal.removeEventListener("abort", onAbort);
      }
    },
  });
}

export function isMcpMethodNotFoundError(error: unknown): boolean {
  if (isRecord(error) && error.code === ErrorCode.MethodNotFound) {
    return true;
  }
  const message = String(error);
  return message.includes("-32601") || /\b(?:method not found|unknown method)\b/i.test(message);
}
