import assert from "node:assert/strict";
import { createRequire } from "node:module";
import path from "node:path";
import { pathToFileURL } from "node:url";
const projectRequire = createRequire(
  path.resolve(process.env.A2UI_TEST_PROJECT ?? process.cwd(), "package.json"),
);
const coreEntry = pathToFileURL(projectRequire.resolve("@a2ui/web_core/v0_9")).href;
const { readFileSync } = await import("node:fs");
const version = JSON.parse(readFileSync(new URL("../../package.json", coreEntry), "utf8")).version;
assert.ok(["0.11.0", "0.12.0"].includes(version));
function checkFunctionParameterResources(core, z, version, generateCatalogSchema) {
  let tree;
  tree = z.lazy(() => z.object({ label: z.string(), children: z.array(tree).optional() }));
  const shared = z.enum(["a", "b"]);
  const fn = {
    name: "check/~",
    schema: z.object({ tree, labels: z.array(shared) }),
    returnType: "boolean",
  };
  const source =
    version === "0.11.0"
      ? new core.Catalog("parameter-fixture", [], [fn])
      : new core.Catalog("parameter-fixture", "0.9", [], [fn]);
  const emitted =
    version === "0.11.0"
      ? new core.MessageProcessor([source]).getClientCapabilities({ includeInlineCatalogs: true })[
          "v0.9"
        ].inlineCatalogs[0]
      : generateCatalogSchema(source);
  if (version === "0.11.0")
    assert.ok(
      emitted.functions[0].parameters.$defs,
      "actual advertised function owns local definitions",
    );
  const round = core.Catalog.fromSchema(emitted).functions.get(fn.name).schema;
  assert.equal(round.safeParse({ tree: { label: "ok" }, labels: ["a"] }).success, true);
  assert.equal(
    round.safeParse({ tree: 42, labels: ["a"] }).success,
    false,
    "parameter-local recursive object type retained",
  );
  assert.equal(
    round.safeParse({ tree: { label: "ok" }, labels: ["bad"] }).success,
    false,
    "shared nonrecursive enum retained",
  );

  const parameter = (kind) => ({
    type: "object",
    properties: { value: { $ref: "#/$defs/Arg" } },
    required: ["value"],
    $defs: { Arg: { type: kind } },
  });
  for (const form of ["array", "object"]) {
    const local = {
      catalogId: "local-resources",
      protocolVersion: "0.9",
      components: {},
      $defs: { Arg: { type: "boolean" } },
      functions:
        form === "array"
          ? [
              { name: "text", parameters: parameter("string") },
              { name: "number", parameters: parameter("number") },
            ]
          : {
              text: { parameters: parameter("string") },
              number: { parameters: parameter("number") },
            },
    };
    const loaded = core.Catalog.fromSchema(local);
    assert.equal(
      loaded.functions.get("text").schema.safeParse({ value: "ok" }).success,
      true,
      form + " string local resource",
    );
    assert.equal(
      loaded.functions.get("text").schema.safeParse({ value: 42 }).success,
      false,
      form + " local string rejects number",
    );
    assert.equal(
      loaded.functions.get("number").schema.safeParse({ value: 42 }).success,
      true,
      form + " independent number resource",
    );
    assert.equal(
      loaded.functions.get("number").schema.safeParse({ value: "bad" }).success,
      false,
      form + " reference cache does not cross resource roots",
    );
    assert.equal(
      loaded.functions.get("number").schema.safeParse({ value: true }).success,
      false,
      form + " local definitions override unrelated catalog definition",
    );
  }
  const full = {
    catalogId: "catalog-root-fallback",
    protocolVersion: "0.9",
    components: {},
    $defs: { GlobalArg: { type: "string" } },
    functions: [
      {
        name: "global",
        parameters: {
          type: "object",
          properties: { value: { $ref: "#/$defs/GlobalArg" } },
          required: ["value"],
        },
      },
    ],
  };
  const globalSchema = core.Catalog.fromSchema(full).functions.get("global").schema;
  assert.equal(
    globalSchema.safeParse({ value: "ok" }).success,
    true,
    "catalog-root fallback remains valid",
  );
  assert.equal(
    globalSchema.safeParse({ value: 42 }).success,
    false,
    "catalog-root fallback retains type validation",
  );
  return {
    advertisedRecursiveFunction: "passed",
    sharedEnum: "passed",
    escapedFunctionName: "passed",
    independentLocalResources: ["array", "object"],
    catalogRootFallback: "passed",
  };
}
let compilationAttempts = 0;
const originalFunction = globalThis.Function;
const originalEval = globalThis.eval;
globalThis.Function = function () {
  compilationAttempts++;
  throw new Error("synthetic strict CSP denies Function");
};
globalThis.eval = function () {
  compilationAttempts++;
  throw new Error("synthetic strict CSP denies eval");
};
try {
  const core = await import(coreEntry);
  const lit = await import(pathToFileURL(projectRequire.resolve("@a2ui/lit/v0_9")));
  const { z } = await import(new URL("../common/zod-runtime.js", coreEntry));
  const require = createRequire(coreEntry);
  assert.equal(require("zod/package.json").version, "4.6.6");
  assert.equal(z.config().jitless, true);
  let visited = 0;
  const child = z.string().superRefine(() => {
    visited++;
  });
  assert.equal(z.array(child).max(1).safeParse(["a", "b"]).success, false);
  assert.equal(visited, 0);
  for (const name of ["A2uiController", "A2uiLitElement", "A2uiSurface", "Context", "basicCatalog"])
    assert.ok(lit[name], name);
  const processor = new core.MessageProcessor([lit.basicCatalog]);
  const caps = processor.getClientCapabilities({
    versions: ["v0.9"],
    version: "v0.9",
    includeInlineCatalogs: true,
  });
  assert.equal(Object.keys(caps["v0.9"].inlineCatalogs[0].components).length, 18);
  assert.equal(lit.basicCatalog.functions.size, version === "0.11.0" ? 25 : 14);
  const actions = [];
  const surface = new core.SurfaceModel("fixture", lit.basicCatalog);
  const schema = z.object({ label: core.CommonSchemas.DynamicString });
  const component = new core.ComponentModel(
    "c1",
    "Fixture",
    { label: { path: "/title" } },
    lit.basicCatalog,
  );
  surface.componentsModel.addComponent(component);
  surface.dataModel.set("/title", "before");
  const context = new core.ComponentContext(surface, "c1");
  let onChangedUpdate;
  const host = {
    context,
    isConnected: true,
    addController(c) {
      this.controller = c;
    },
    requestUpdate() {
      actions.push("update");
      if (this.controller?.props.label === "after") onChangedUpdate?.();
    },
  };
  const controller = new lit.A2uiController(host, { name: "Fixture", schema });
  assert.equal(controller.props.label, "before");
  const changedUpdate = new Promise((resolve) => {
    onChangedUpdate = resolve;
  });
  surface.dataModel.set("/title", "after");
  await changedUpdate;
  assert.equal(controller.props.label, "after");
  assert.ok(actions.length > 0);
  controller.dispose();
  const legacy = await import(new URL("../v0_8/schema/server-to-client.js", coreEntry));
  assert.equal(typeof legacy.A2uiMessageSchema.safeParse, "function");
  assert.equal(legacy.A2uiMessageSchema.safeParse({ bogus: true }).success, false);

  {
    const preprocess = z.preprocess(
      (value) => value,
      z.object({ child: core.CommonSchemas.ComponentId }),
    );
    assert.equal(core.scrapeSchemaBehavior(preprocess).type, "OBJECT", "preprocessed object shape");
    assert.equal(
      core.extractRefFields(preprocess).get("child")?.kind,
      "single",
      "preprocessed child reference",
    );
    if (version === "0.12.0")
      assert.deepEqual(
        [...core.getKnownSchemaKeys(preprocess)],
        ["child"],
        "preprocess function argument allowlist",
      );
    const validatorPipe = z
      .any()
      .superRefine(() => {})
      .pipe(z.object({ label: core.CommonSchemas.DynamicString }));
    assert.equal(
      core.scrapeSchemaBehavior(validatorPipe).shape.label.type,
      "DYNAMIC",
      "oneOf validator-only input exposes output shape",
    );
    const createRecursive = () => {
      let node;
      node = z.lazy(() => z.object({ label: z.string(), children: z.array(node).optional() }));
      return node;
    };
    const apis = [
      { name: "RecursiveA", schema: createRecursive() },
      { name: "RecursiveB", schema: createRecursive() },
    ];
    const catalog =
      version === "0.11.0"
        ? new core.Catalog("fixture", apis)
        : new core.Catalog("fixture", "0.9", apis);
    const processor = new core.MessageProcessor([catalog]);
    const inline = processor.getClientCapabilities({
      version: "v0.9",
      versions: ["v0.9"],
      includeInlineCatalogs: true,
    })["v0.9"].inlineCatalogs[0];
    for (const name of ["RecursiveA", "RecursiveB"]) {
      const component = inline.components[name];
      const document = component;
      const property = component.allOf[1].properties.children;
      const targetRef = property.items.$ref;
      assert.ok(targetRef?.startsWith("#/$defs/"), "recursive references are explicitly anchored");
      let target = document;
      for (const token of targetRef.slice(2).split("/")) {
        target = target[token.replaceAll("~1", "/").replaceAll("~0", "~")];
        assert.ok(target, "reference resolves after catalog embedding");
      }
      assert.equal(target.type, "object");
      assert.equal(
        target.properties.label.type,
        "string",
        "reference points to recursive object rather than catalog",
      );
      assert.equal(
        target.properties.component,
        undefined,
        "reference does not acquire outer component envelope",
      );
      assert.equal(
        target.properties.children.items.$ref,
        targetRef,
        "recursion remains self-consistent",
      );
    }
    if (version === "0.12.0") {
      const { generateCatalogSchema } = await import(
        new URL("../catalog/schema_generator.js", coreEntry)
      );
      const full = generateCatalogSchema(catalog);
      for (const name of ["RecursiveA", "RecursiveB"]) {
        const ref = full.components[name].properties.children.items.$ref;
        let target = full;
        for (const token of ref.slice(2).split("/"))
          target = target[token.replaceAll("~1", "/").replaceAll("~0", "~")];
        assert.equal(target.properties.label.type, "string");
        assert.equal(target.properties.component, undefined);
      }
    }
  }
  {
    const { zodToJsonSchema } = await import(new URL("../common/zod-json-schema.js", coreEntry));
    const shared = z.string().min(2);
    const schema = z
      .object({
        required: shared,
        alsoRequired: shared,
        optional: z.boolean().optional(),
        defaulted: z.string().default("fixture"),
        rows: z.array(z.number()).max(1),
        transformed: z.string().transform((value) => value.length),
      })
      .strict();
    const options = { target: "jsonSchema2019-09", $refStrategy: "none" };
    const generated = zodToJsonSchema(schema, options);
    assert.deepEqual(options, { target: "jsonSchema2019-09", $refStrategy: "none" });
    assert.equal(generated.$schema, "https://json-schema.org/draft/2020-12/schema");
    assert.deepEqual(generated.required, ["required", "alsoRequired", "rows", "transformed"]);
    assert.equal(generated.properties.required.minLength, 2);
    assert.equal(generated.properties.alsoRequired.minLength, 2);
    assert.equal(generated.properties.required.$ref, undefined);
    assert.equal(generated.properties.alsoRequired.$ref, undefined);
    assert.equal(generated.properties.rows.maxItems, 1);
    assert.equal(generated.properties.defaulted.default, "fixture");
    assert.equal(generated.properties.transformed.type, "string");
    assert.equal(generated.additionalProperties, false);
    assert.throws(
      () => zodToJsonSchema(schema, { target: "openAi" }),
      /Unsupported A2UI JSON Schema target/,
    );
    assert.throws(
      () => zodToJsonSchema(schema, { $refStrategy: "relative" }),
      /Unsupported A2UI JSON Schema reference strategy/,
    );
    let recursive;
    recursive = z.lazy(() =>
      z.object({ value: z.string(), children: z.array(recursive).optional() }),
    );
    const recursiveJson = zodToJsonSchema(recursive, options);
    let refs = 0;
    function validateRefs(value) {
      if (!value || typeof value !== "object") return;
      if (typeof value.$ref === "string") {
        assert.ok(value.$ref.startsWith("#"));
        let cursor = recursiveJson;
        for (const token of value.$ref.slice(2).split("/").filter(Boolean)) {
          cursor = cursor[token.replaceAll("~1", "/").replaceAll("~0", "~")];
          assert.ok(cursor);
        }
        refs++;
      }
      for (const child of Object.values(value)) validateRefs(child);
    }
    validateRefs(recursiveJson);
    assert.ok(refs > 0);
  }
  if (version === "0.12.0") {
    const { formatZodIssue } = await import(
      new URL("../processing/format-zod-issue.js", coreEntry)
    );
    for (const [schema, input] of [
      [z.string(), 42],
      [z.enum(["primary", "secondary"]), "synthetic-private-marker"],
    ]) {
      const issue = schema.safeParse(input).error.issues[0];
      assert.equal(Object.hasOwn(issue, "input"), false);
      assert.equal(formatZodIssue(issue), `root: ${issue.message}`);
      assert.equal(formatZodIssue(issue).includes("synthetic-private-marker"), false);
    }
    const issue = z
      .string()
      .safeParse({ privateMarker: "synthetic-private-marker" }, { reportInput: true }).error
      .issues[0];
    assert.equal(Object.hasOwn(issue, "input"), true);
    assert.equal(formatZodIssue(issue), `root: ${issue.message}`);
    assert.equal(formatZodIssue(issue).includes("synthetic-private-marker"), false);
  }
  const generate =
    version === "0.12.0"
      ? (await import(new URL("../catalog/schema_generator.js", coreEntry))).generateCatalogSchema
      : undefined;
  checkFunctionParameterResources(core, z, version, generate);
  assert.equal(compilationAttempts, 0);
  console.log(
    JSON.stringify({
      version,
      zod: "4.6.6",
      catalogComponents: 18,
      catalogFunctions: lit.basicCatalog.functions.size,
      litReactiveBinding: "passed",
      legacySchema: "passed",
      nativeBoundedCollection: "passed",
      strictCsp: { dynamicCompilationAvailable: false, compilationAttempts },
      qualification: "package-level synthetic, no browser render or application image claim",
    }),
  );
} finally {
  globalThis.Function = originalFunction;
  globalThis.eval = originalEval;
}
