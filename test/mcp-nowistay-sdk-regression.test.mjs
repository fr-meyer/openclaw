import assert from "node:assert/strict";
import fs from "node:fs";
import { stripTypeScriptTypes } from "node:module";
import path from "node:path";
import test from "node:test";
import { pathToFileURL } from "node:url";

const sdkClientUrl = process.env.NOWISTAY_COMPAT_SDK_ROOT
  ? pathToFileURL(path.join(process.env.NOWISTAY_COMPAT_SDK_ROOT, "dist/esm/client/index.js")).href
  : import.meta.resolve("@modelcontextprotocol/sdk/client/index.js");
const sdkEsmRoot = new URL("../", sdkClientUrl);
const { Client } = await import(sdkClientUrl);
const { StreamableHTTPClientTransport } = await import(
  new URL("client/streamableHttp.js", sdkEsmRoot)
);
const moduleUrl = (source) =>
  `data:text/javascript;base64,${Buffer.from(source).toString("base64")}`;
const helperSource = stripTypeScriptTypes(
  fs.readFileSync(
    new URL("../src/agents/mcp-http-tool-schema-compatibility.ts", import.meta.url),
    "utf8",
  ),
).replace(
  '"@openclaw/normalization-core/record-coerce"',
  JSON.stringify(import.meta.resolve("@openclaw/normalization-core/record-coerce")),
);
const httpSource = stripTypeScriptTypes(
  fs.readFileSync(new URL("../src/agents/mcp-http-transport.ts", import.meta.url), "utf8"),
)
  .replace(/"@modelcontextprotocol\/sdk\/([^"]+)"/g, (_match, suffix) =>
    JSON.stringify(new URL(suffix, sdkEsmRoot).href),
  )
  .replace('"./mcp-http-tool-schema-compatibility.js"', JSON.stringify(moduleUrl(helperSource)));
const { OpenClawStreamableHTTPClientTransport } = await import(moduleUrl(httpSource));
const publishedSchema = JSON.parse(
  fs.readFileSync(
    new URL("./fixtures/nowistay-list-properties-output-schema.json", import.meta.url),
  ),
);
const endpoint = "https://api.nowistay.com/mcp";
const baselineItem = {
  id: 1,
  name: "Synthetic fixture",
  aiAssistantEnabled: false,
  nowistayPmsConnected: true,
};

async function callFixture({
  item,
  schema = publishedSchema,
  url = endpoint,
  toolName = "list_properties",
  native = true,
}) {
  const payload = { items: [item], pagination: {} };
  const fakeFetch = async (_url, init) => {
    if (init?.method === "GET") {
      return new Response(null, { status: 405 });
    }
    if (init?.method === "DELETE") {
      return new Response(null, { status: 200 });
    }
    const request = JSON.parse(init.body);
    if (request.id === undefined) {
      return new Response(null, { status: 202 });
    }
    let result;
    if (request.method === "initialize") {
      result = {
        protocolVersion: "2025-06-18",
        capabilities: { tools: {} },
        serverInfo: { name: "synthetic-contract-fixture", version: "1" },
      };
    } else if (request.method === "tools/list") {
      result = {
        tools: [
          {
            name: toolName,
            inputSchema: { type: "object" },
            outputSchema: structuredClone(schema),
            annotations: { readOnlyHint: true },
          },
        ],
      };
    } else if (request.method === "tools/call") {
      result = {
        content: [{ type: "text", text: "Synthetic fixture; no business data" }],
        structuredContent: structuredClone(payload),
        isError: false,
      };
    } else {
      throw new Error(`Unexpected synthetic method: ${request.method}`);
    }
    return new Response(JSON.stringify({ jsonrpc: "2.0", id: request.id, result }), {
      headers: { "Content-Type": "application/json" },
    });
  };
  const transport = native
    ? new OpenClawStreamableHTTPClientTransport(new URL(url), { fetch: fakeFetch })
    : new StreamableHTTPClientTransport(new URL(url), { fetch: fakeFetch });
  const client = new Client({ name: "synthetic-read-only-contract-test", version: "1" });
  try {
    await client.connect(transport, { timeout: 1_000 });
    await client.listTools({}, { timeout: 1_000 });
    const result = await client.callTool({ name: toolName, arguments: {} }, undefined, {
      timeout: 1_000,
    });
    assert.equal(result.isError, false);
    assert.deepEqual(result.structuredContent, payload, "Returned data must remain intact");
    return result;
  } finally {
    const cleanup = await Promise.allSettled([client.close(), transport.close()]);
    assert.equal(
      cleanup.some((entry) => entry.status === "rejected"),
      false,
    );
  }
}

const rejectsOutput = (promise) =>
  assert.rejects(
    promise,
    (error) => error.code === -32602 && /Structured content does not match/.test(error.message),
  );

test("actual SDK reproduces the original provider defect without the compatibility owner", async () => {
  await rejectsOutput(callFixture({ native: false, item: { ...baselineItem, vatRate: null } }));
});

for (const vatRate of [null, 0, 20, 100]) {
  test(`actual SDK accepts the compatible nullable percentage (${vatRate}) without dropping data`, async () => {
    await callFixture({ item: { ...baselineItem, vatRate } });
  });
}

for (const vatRate of [-1, 101, "20", true, {}]) {
  test(`actual SDK rejects an invalid VAT value (${JSON.stringify(vatRate)})`, async () => {
    await rejectsOutput(callFixture({ item: { ...baselineItem, vatRate } }));
  });
}

test("actual SDK still rejects unrelated additional fields", async () => {
  await rejectsOutput(
    callFixture({ item: { ...baselineItem, vatRate: null, forbiddenField: "fixture" } }),
  );
});

test("actual SDK still enforces existing field types and required properties", async () => {
  await rejectsOutput(callFixture({ item: { ...baselineItem, id: "invalid", vatRate: null } }));
  const missing = { ...baselineItem, vatRate: null };
  delete missing.id;
  await rejectsOutput(callFixture({ item: missing }));
});

test("actual SDK still rejects the same response for another endpoint or tool", async () => {
  await rejectsOutput(
    callFixture({ url: "https://other.example/mcp", item: { ...baselineItem, vatRate: null } }),
  );
  await rejectsOutput(
    callFixture({ toolName: "another_tool", item: { ...baselineItem, vatRate: null } }),
  );
});

test("unfamiliar provider schema stays strict", async () => {
  const schema = structuredClone(publishedSchema);
  schema.description = "Future unknown provider version";
  await rejectsOutput(callFixture({ schema, item: { ...baselineItem, vatRate: null } }));
});

test("an upstream schema correction is preserved", async () => {
  const schema = structuredClone(publishedSchema);
  schema.properties.items.items.properties.vatRate = { type: ["number", "null"] };
  await callFixture({ schema, item: { ...baselineItem, vatRate: null } });
});
