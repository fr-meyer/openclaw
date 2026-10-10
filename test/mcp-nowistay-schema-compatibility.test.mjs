import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import { stripTypeScriptTypes } from "node:module";

// Node's plain test runner does not resolve the private workspace package alias.
// Load the same source the production build uses, with only that import resolved.
const compatibilitySource = stripTypeScriptTypes(
  fs.readFileSync(new URL("../src/agents/mcp-http-tool-schema-compatibility.ts", import.meta.url), "utf8"),
).replace(
  '"@openclaw/normalization-core/record-coerce"',
  JSON.stringify(new URL("../packages/normalization-core/src/record-coerce.ts", import.meta.url).href),
);
const { McpHttpToolSchemaCompatibility } = await import(
  `data:text/javascript;base64,${Buffer.from(compatibilitySource).toString("base64")}`,
);

const publishedSchema = JSON.parse(
  fs.readFileSync(
    new URL("./fixtures/nowistay-list-properties-output-schema.json", import.meta.url),
  ),
);
const endpoint = "https://api.nowistay.com/mcp";
const request = (id = 1, method = "tools/list") => ({ jsonrpc: "2.0", id, method });
const response = (id = 1, schema = publishedSchema, toolName = "list_properties") => ({
  jsonrpc: "2.0",
  id,
  result: {
    tools: [{ name: toolName, outputSchema: structuredClone(schema) }],
    nextCursor: "preserved-pagination-token",
  },
});
const itemSchema = (message) => message.result.tools[0].outputSchema.properties.items.items;

test("repairs only the known nullable VAT omission without mutating its source", () => {
  const owner = new McpHttpToolSchemaCompatibility(new URL(endpoint));
  const original = response();
  const snapshot = structuredClone(original);
  owner.recordRequest(request());
  const normalized = owner.normalizeResponse(original);
  assert.notEqual(normalized, original);
  assert.deepEqual(original, snapshot);
  assert.deepEqual(itemSchema(normalized).properties.vatRate, {
    type: ["number", "null"],
    minimum: 0,
    maximum: 100,
  });
  const recovered = structuredClone(normalized);
  delete itemSchema(recovered).properties.vatRate;
  assert.deepEqual(recovered, original);
  assert.equal(itemSchema(normalized).additionalProperties, false);
  assert.equal(normalized.result.nextCursor, original.result.nextCursor);
});

test("leaves other providers, origins, ports, paths, credentials and queries unchanged", () => {
  for (const url of [
    "https://mcp.pricelabs.co/",
    "http://api.nowistay.com/mcp",
    "https://api.nowistay.com/other",
    "https://api.nowistay.com:444/mcp",
    "https://api.nowistay.com/mcp?tenant=fixture",
    "https://api.nowistay.com/mcp#fixture",
    "https://user:fixture@api.nowistay.com/mcp",
    "https://api.nowistay.com.example/mcp",
  ]) {
    const owner = new McpHttpToolSchemaCompatibility(new URL(url));
    const message = response();
    owner.recordRequest(request());
    assert.equal(owner.normalizeResponse(message), message, url);
  }
});

test("leaves every other tool unchanged even with an identical schema", () => {
  const owner = new McpHttpToolSchemaCompatibility(new URL(endpoint));
  const message = response(1, publishedSchema, "list_bookings");
  owner.recordRequest(request());
  assert.equal(owner.normalizeResponse(message), message);
});

test("does not reinterpret tool-call results as tools/list metadata", () => {
  const owner = new McpHttpToolSchemaCompatibility(new URL(endpoint));
  const message = response();
  owner.recordRequest(request(1, "tools/call"));
  assert.equal(owner.normalizeResponse(message), message);
});

test("requires the exact schema and preserves upstream fixes", () => {
  for (const change of [
    (s) => {
      s.description = "Future provider contract";
    },
    (s) => {
      s.properties.items.items.additionalProperties = true;
    },
    (s) => {
      s.properties.items.items.properties.vatRate = { type: "string" };
    },
    (s) => {
      s.properties.items.items.required.push("futureField");
    },
  ]) {
    const schema = structuredClone(publishedSchema);
    change(schema);
    const owner = new McpHttpToolSchemaCompatibility(new URL(endpoint));
    const message = response(1, schema);
    if (schema === undefined) {
      delete message.result.tools[0].outputSchema;
    }
    owner.recordRequest(request());
    assert.equal(owner.normalizeResponse(message), message);
  }
});

test("matches parallel paginated requests by exact string or numeric ID", () => {
  const owner = new McpHttpToolSchemaCompatibility(new URL(endpoint));
  owner.recordRequest(request(1));
  owner.recordRequest(request("page-two"));
  const serverRequest = request(1, "ping");
  assert.equal(owner.normalizeResponse(serverRequest), serverRequest);
  const unrelated = response("1");
  assert.equal(owner.normalizeResponse(unrelated), unrelated);
  for (const id of ["page-two", 1]) {
    const message = response(id);
    assert.notEqual(owner.normalizeResponse(message), message);
    assert.equal(owner.normalizeResponse(message), message);
  }
});

test("clears failed, cancelled and closed request ownership", () => {
  for (const end of [
    (o) => o.forgetRequest(request()),
    (o) =>
      o.recordRequest({
        jsonrpc: "2.0",
        method: "notifications/cancelled",
        params: { requestId: 1 },
      }),
    (o) => o.clear(),
    (o) =>
      o.normalizeResponse({ jsonrpc: "2.0", id: 1, error: { code: -32603, message: "fixture" } }),
  ]) {
    const owner = new McpHttpToolSchemaCompatibility(new URL(endpoint));
    owner.recordRequest(request());
    end(owner);
    const message = response();
    assert.equal(owner.normalizeResponse(message), message);
  }
});

test("forwards malformed and unknown metadata for ordinary validation", () => {
  for (const schema of [undefined, null, {}, { type: "object", properties: { items: [] } }]) {
    const owner = new McpHttpToolSchemaCompatibility(new URL(endpoint));
    const message = response();
    message.result.tools[0].outputSchema = schema;
    owner.recordRequest(request());
    assert.equal(owner.normalizeResponse(message), message);
  }
});
