import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { dirname, resolve } from "node:path";
import test from "node:test";
import { pathToFileURL } from "node:url";

const require = createRequire(import.meta.url);
const coreEntry = require.resolve("@a2ui/web_core/v0_9");
const coreRequire = createRequire(coreEntry);
const zodPackage = coreRequire.resolve("zod/package.json");
assert.equal(coreRequire("zod/package.json").version, "4.6.6");
const esm = await import(pathToFileURL(resolve(dirname(zodPackage), "index.js")).href);
const cjs = coreRequire("zod");

for (const [format, { z }] of [
  ["ESM", esm],
  ["CJS", cjs],
]) {
  for (const async of [false, true]) {
    const parse = (schema, input) =>
      async ? schema.safeParseAsync(input) : schema.safeParse(input);
    for (const kind of ["array max", "array exact", "set max", "set exact"]) {
      test(`${format} ${async ? "async" : "sync"} ${kind} rejects before element/outer work`, async () => {
        let elements = 0;
        let outer = 0;
        const element = z.string().refine(() => {
          elements++;
          return true;
        });
        const collection = kind.startsWith("array") ? z.array(element) : z.set(element);
        const bounded = kind.endsWith("max")
          ? collection.max(2, "bounded")
          : kind.startsWith("array")
            ? collection.length(2, "bounded")
            : collection.size(2, "bounded");
        const schema = z.object({
          values: bounded.refine(() => {
            outer++;
            return true;
          }),
        });
        const values = kind.startsWith("array") ? ["a", "b", "c"] : new Set(["a", "b", "c"]);
        const result = await parse(schema, { values });
        assert.equal(result.success, false);
        assert.deepEqual([elements, outer], [0, 0]);
        assert.equal(result.error.issues.length, 1);
        assert.equal(result.error.issues[0].code, "too_big");
        assert.deepEqual(result.error.issues[0].path, ["values"]);
        assert.equal(result.error.issues[0].message, "bounded");
      });
    }
    test(`${format} ${async ? "async" : "sync"} preserves valid transforms, lower bounds, unions and wrong types`, async () => {
      const arr = z.array(z.string().transform((s) => s.toUpperCase())).max(2);
      assert.deepEqual((await parse(arr, ["a", "b"])).data, ["A", "B"]);
      assert.equal(
        (await parse(z.array(z.string()).length(2), ["a"])).error.issues[0].code,
        "too_small",
      );
      assert.equal(
        (await parse(z.set(z.string()).min(2), new Set(["a"]))).error.issues[0].code,
        "too_small",
      );
      assert.equal((await parse(arr, {})).error.issues[0].code, "invalid_type");
      assert.equal(
        (await parse(z.set(z.string()).max(1), [])).error.issues[0].code,
        "invalid_type",
      );
      assert.equal(
        (await parse(z.union([z.array(z.string()).max(1), z.literal("fallback")]), ["a", "b"]))
          .error.issues[0].code,
        "invalid_union",
      );
      assert.equal(
        (await parse(z.union([arr, z.literal("fallback")]), "fallback")).data,
        "fallback",
      );
      assert.deepEqual(
        (
          await parse(
            z.preprocess((v) => v.slice(0, 2), arr),
            ["a", "b", "c"],
          )
        ).data,
        ["A", "B"],
      );
    });
  }
}

test("A2UI 0.12 public v0_9 Catalog argument schema uses the selected native bounded parser", async () => {
  const { Catalog } = await import("@a2ui/web_core/v0_9");
  const catalog = Catalog.fromSchema(
    {
      catalogId: "urn:openclaw:bounds-test",
      protocolVersion: "0.9",
      components: {},
      functions: {
        bounded: {
          parameters: {
            type: "object",
            properties: { values: { type: "array", maxItems: 1, items: { type: "string" } } },
            required: ["values"],
          },
          returnType: "string",
        },
      },
    },
    "0.9",
  );
  const fn = catalog.functions.get("bounded");
  assert.ok(fn);
  const field = fn.schema.shape.values;
  // The schema is created by the shipped A2UI loader, not a replacement schema.
  assert.equal(esm.toJSONSchema(field).maxItems, 1);
  let visited = 0;
  const oversized = Array(2);
  for (let index = 0; index < oversized.length; index++) {
    Object.defineProperty(oversized, String(index), {
      get() {
        visited++;
        return "a";
      },
    });
  }
  const invalid = fn.schema.safeParse({ values: oversized });
  assert.equal(invalid.success, false);
  assert.equal(visited, 0);
  assert.equal(invalid.error.issues[0].code, "too_big");
  assert.deepEqual(invalid.error.issues[0].path, ["values"]);
  assert.equal(fn.schema.safeParse({ values: ["a"] }).success, true);
  assert.ok(catalog.catalogSchema);
});
