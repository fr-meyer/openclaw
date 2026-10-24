import assert from "node:assert/strict";
import { createRequire } from "node:module";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { runInThisContext } from "node:vm";
const projectRequire = createRequire(
  path.resolve(process.env.A2UI_TEST_PROJECT ?? process.cwd(), "package.json"),
);
const coreEntry = pathToFileURL(projectRequire.resolve("@a2ui/web_core/v0_9")).href;
const { readFileSync } = await import("node:fs");
const version = JSON.parse(readFileSync(new URL("../../package.json", coreEntry), "utf8")).version;
assert.ok(["0.11.0", "0.12.0"].includes(version));
function observeProtocolAliasPrecedence(core) {
  const schema = (local, reference, global = {}) => {
    const parameters = {
      type: "object",
      $defs: local,
      properties: { value: { $ref: reference } },
      required: ["value"],
    };
    const catalog = {
      catalogId: "local-protocol-fixture",
      protocolVersion: "0.9",
      components: {},
      $defs: global,
      functions: { check: { parameters } },
    };
    return core.Catalog.fromSchema(catalog, "0.9").functions.get("check").schema;
  };

  const cases = [
    [
      "local-ComponentId",
      schema({ ComponentId: { type: "number" } }, "#/$defs/ComponentId"),
      42,
      "local-string",
    ],
    [
      "local-DynamicNumber",
      schema({ DynamicNumber: { type: "string" } }, "#/$defs/DynamicNumber"),
      "local-string",
      42,
    ],
    [
      "external-protocol",
      schema({ ComponentId: { type: "number" } }, "common_types.json#/$defs/ComponentId"),
      "protocol-string",
      42,
    ],
    [
      "missing-local-protocol",
      schema({ Unused: { type: "number" } }, "#/$defs/ComponentId"),
      "protocol-string",
      42,
    ],
    [
      "catalog-protocol-compatibility",
      schema({ Unused: { type: "number" } }, "#/$defs/ComponentId", {
        ComponentId: { type: "number" },
      }),
      "protocol-string",
      42,
    ],
    [
      "local-alias-context",
      schema(
        { ComponentId: { type: "number" }, Alias: { $ref: "#/$defs/ComponentId" } },
        "#/$defs/Alias",
      ),
      42,
      "local-string",
    ],
  ];
  return cases.map(([name, validator, valid, invalid]) => ({
    name,
    acceptsExpected: validator.safeParse({ value: valid }).success,
    rejectsUnexpected: !validator.safeParse({ value: invalid }).success,
  }));
}
function checkProtocolAliasPrecedence(core) {
  const checks = observeProtocolAliasPrecedence(core);
  for (const c of checks) {
    assert.equal(c.acceptsExpected, true, c.name + " accepts its declared schema");
    assert.equal(c.rejectsUnexpected, true, c.name + " rejects the other type");
  }
  return {
    localAliases: "passed",
    externalProtocol: "preserved",
    missingLocalProtocol: "preserved",
    catalogProtocolCompatibility: "preserved",
    nestedLocalContext: "passed",
  };
}
function componentContextFixture(core, z, fixtureVersion) {
  const recursive = () => {
    const node = z.lazy(() => z.object({ label: z.string(), children: z.array(node).optional() }));
    return node;
  };
  const components = [
    { name: "WrappedA", schema: z.object({ tree: recursive() }) },
    { name: "WrappedB", schema: z.object({ tree: recursive() }) },
  ];
  const source =
    fixtureVersion === "0.11.0"
      ? new core.Catalog("component-fixture", components)
      : new core.Catalog("component-fixture", "0.9", components);
  const processor = new core.MessageProcessor([source]);
  const inline = processor.getClientCapabilities({
    versions: ["v0.9"],
    version: "v0.9",
    includeInlineCatalogs: true,
  })["v0.9"].inlineCatalogs[0];
  return { source, inline, loaded: core.Catalog.fromSchema(inline, "0.9") };
}
function checkComponentReferenceContexts(core, z, fixtureVersion) {
  const { source, inline, loaded } = componentContextFixture(core, z, fixtureVersion);
  for (const name of ["WrappedA", "WrappedB"]) {
    assert.equal(source.components.get(name).schema.safeParse({ tree: 42 }).success, false);
    const restored = loaded.components.get(name).schema;
    assert.equal(
      restored.safeParse({ tree: { label: "ok", children: [{ label: "nested" }] } }).success,
      true,
      "emitted wrapped recursive component reopens",
    );
    assert.equal(
      restored.safeParse({ tree: 42 }).success,
      false,
      "wrapped recursive field retains its previously-enforced object type",
    );
  }
  const create = (kind) => ({
    $defs: { Shared: { type: kind } },
    properties: { value: { $ref: "#/$defs/Shared" }, global: { $ref: "#/$defs/Global" } },
    required: ["value", "global"],
  });
  const catalog = {
    catalogId: "component-context",
    protocolVersion: "0.9",
    $defs: {
      Global: { type: "boolean" },
      Shared: { type: "string" },
      GlobalPart: {
        properties: { fromGlobal: { $ref: "#/$defs/Shared" } },
        required: ["fromGlobal"],
      },
    },
    components: {
      Text: create("string"),
      Number: create("number"),
      Mixed: {
        $defs: { Shared: { type: "number" } },
        allOf: [
          { $ref: "#/$defs/GlobalPart" },
          { properties: { fromLocal: { $ref: "#/$defs/Shared" } }, required: ["fromLocal"] },
        ],
      },
    },
  };
  const parsed = core.Catalog.fromSchema(catalog, "0.9");
  assert.equal(
    parsed.components.get("Text").schema.safeParse({ value: "ok", global: true }).success,
    true,
  );
  assert.equal(
    parsed.components.get("Text").schema.safeParse({ value: 42, global: true }).success,
    false,
  );
  assert.equal(
    parsed.components.get("Number").schema.safeParse({ value: 42, global: false }).success,
    true,
    "component-local cache is independent",
  );
  assert.equal(
    parsed.components.get("Number").schema.safeParse({ value: "bad", global: false }).success,
    false,
  );
  const mixed = parsed.components.get("Mixed").schema;
  assert.equal(
    mixed.safeParse({ fromGlobal: "global-string", fromLocal: 42 }).success,
    true,
    "global allOf part retains original catalog lookup context",
  );
  assert.equal(
    mixed.safeParse({ fromGlobal: 42, fromLocal: 42 }).success,
    false,
    "global allOf alias cannot rebind to local collision",
  );
  assert.equal(
    mixed.safeParse({ fromGlobal: "global-string", fromLocal: "bad" }).success,
    false,
    "local context retains priority",
  );
  const oldProtocol = core.Catalog.fromSchema(
    {
      catalogId: "component-protocol",
      components: {
        Fixture: {
          $defs: { ComponentId: { type: "number" } },
          properties: {
            value: { $ref: "#/$defs/ComponentId" },
            external: { $ref: "common_types.json#/$defs/ComponentId" },
          },
          required: ["value", "external"],
        },
      },
    },
    "0.9",
  ).components.get("Fixture").schema;
  assert.equal(
    oldProtocol.safeParse({ value: "legacy-string", external: "protocol-string" }).success,
    true,
    "component canonical shortcuts remain compatible",
  );
  assert.equal(oldProtocol.safeParse({ value: 42, external: "protocol-string" }).success, false);
  return {
    wrappedComponentType: "preserved",
    twoComponentContexts: "isolated",
    catalogFallback: "preserved",
    allOfGlobalContext: "preserved",
    componentProtocolCompatibility: "preserved",
    deepRecursion: "not-newly-claimed",
    inline,
  };
}
function checkOwnReferenceRoots(core, publishedControl = false) {
  const create = (name, local) => {
    const parameters = {
      type: "object",
      $defs: local,
      properties: { value: { $ref: `#/$defs/${name}/properties/value` } },
      required: ["value"],
    };
    const catalog = {
      catalogId: "own-reference-fixture",
      protocolVersion: "0.9",
      components: {},
      $defs: Object.fromEntries([[name, { properties: { value: { type: "string" } } }]]),
      functions: { check: { parameters } },
    };
    return core.Catalog.fromSchema(catalog, "0.9").functions.get("check").schema;
  };

  for (const name of ["constructor", "toString"]) {
    const absent = create(name, { Unused: { type: "number" } });
    assert.equal(
      absent.safeParse({ value: "ok" }).success,
      true,
      "absent own local " + name + " falls back to own catalog definition",
    );
    assert.equal(
      absent.safeParse({ value: 42 }).success,
      false,
      "catalog " + name + " type remains enforced",
    );
    if (publishedControl) {
      continue;
    }
    const own = create(
      name,
      Object.fromEntries([[name, { properties: { value: { type: "number" } } }]]),
    );
    assert.equal(
      own.safeParse({ value: 42 }).success,
      true,
      "own local " + name + " retains priority",
    );
    assert.equal(own.safeParse({ value: "bad" }).success, false);
    const inherited = Object.create(
      Object.fromEntries([[name, { properties: { value: { type: "number" } } }]]),
    );
    inherited.Unused = { type: "boolean" };
    const before = Object.getPrototypeOf(inherited);
    const schema = create(name, inherited);
    assert.equal(
      schema.safeParse({ value: "ok" }).success,
      true,
      "inherited object target does not preempt catalog " + name,
    );
    assert.equal(schema.safeParse({ value: 42 }).success, false);
    assert.equal(
      Object.getPrototypeOf(inherited),
      before,
      "no caller or global prototype mutation",
    );
    assert.equal(Object.hasOwn(inherited, name), false);
  }
  return publishedControl
    ? {
        scope: "published own catalog constructor/toString nested-schema fallback controls only",
        absentOwnLocalCatalogFallback: "passed",
        catalogTypeGuard: "passed",
      }
    : {
        ownLocalPriority: "passed",
        absentOwnLocalCatalogFallback: "passed",
        inheritedObjectCannotPreemptFallback: "passed",
        prototypeMutation: false,
      };
}
function checkMixedReferenceContexts(core, fixtureVersion) {
  const parameters = (properties, $defs) => ({
    type: "object",
    properties,
    required: Object.keys(properties),
    $defs,
  });
  const load = (definitions, params) =>
    core.Catalog.fromSchema(
      {
        $schema: "https://json-schema.org/draft/2020-12/schema",
        catalogId: "custom-full-catalog",
        protocolVersion: "0.9",
        components: {},
        $defs: definitions,
        functions: { check: { name: "check", returnType: "boolean", parameters: params } },
      },
      "0.9",
    ).functions.get("check").schema;
  const global = load(
    { Shared: { type: "string" } },
    parameters({ value: { $ref: "#/$defs/Shared" } }, { Unused: { type: "number" } }),
  );
  assert.equal(
    global.safeParse({ value: "ok" }).success,
    true,
    "published custom-catalog global reference remains valid",
  );
  assert.equal(
    global.safeParse({ value: 42 }).success,
    false,
    "catalog type guard remains enforced with unused local definitions",
  );
  const mixed = load(
    { Shared: { type: "string" } },
    parameters(
      { global: { $ref: "#/$defs/Shared" }, local: { $ref: "#/$defs/Local" } },
      { Local: { type: "number" } },
    ),
  );
  assert.equal(mixed.safeParse({ global: "ok", local: 42 }).success, true);
  assert.equal(mixed.safeParse({ global: 42, local: 42 }).success, false);
  assert.equal(mixed.safeParse({ global: "ok", local: "bad" }).success, false);
  for (const reverse of [false, true]) {
    const properties = {
      local: { $ref: "#/$defs/Shared" },
      localAlias: { $ref: "#/$defs/LocalAlias" },
      globalAlias: { $ref: "#/$defs/GlobalAlias" },
    };
    const ordered = reverse
      ? Object.fromEntries(Object.entries(properties).toReversed())
      : properties;
    const collisions = load(
      { Shared: { type: "string" }, GlobalAlias: { $ref: "#/$defs/Shared" } },
      parameters(ordered, { Shared: { type: "number" }, LocalAlias: { $ref: "#/$defs/Shared" } }),
    );
    assert.equal(
      collisions.safeParse({ local: 42, localAlias: 1, globalAlias: "ok" }).success,
      true,
      "fallback definition retains its own global lookup context",
    );
    assert.equal(
      collisions.safeParse({ local: "bad", localAlias: 1, globalAlias: "ok" }).success,
      false,
      "local definitions win",
    );
    assert.equal(
      collisions.safeParse({ local: 42, localAlias: 1, globalAlias: 42 }).success,
      false,
      "global nested refs do not bind to local cache entries",
    );
  }
  const sharedParameters = parameters(
    { value: { $ref: "#/$defs/Shared" } },
    { Unused: { type: "boolean" } },
  );
  const original = structuredClone(sharedParameters);
  const first = load({ Shared: { type: "string" } }, sharedParameters);
  const second = load({ Shared: { type: "number" } }, sharedParameters);
  assert.equal(second.safeParse({ value: 42 }).success, true);
  assert.equal(second.safeParse({ value: "bad" }).success, false);
  assert.equal(
    first.safeParse({ value: "ok" }).success,
    true,
    "reused input object does not rebind the first catalog",
  );
  assert.equal(first.safeParse({ value: 42 }).success, false);
  assert.deepEqual(sharedParameters, original, "caller schema is not mutated");
  const catalog = {
    catalogId: "per-resource-cache",
    protocolVersion: "0.9",
    components: {},
    $defs: { Global: { type: "boolean" } },
    functions: {
      text: {
        parameters: parameters(
          { value: { $ref: "#/$defs/Shared" }, global: { $ref: "#/$defs/Global" } },
          { Shared: { type: "string" } },
        ),
      },
      number: {
        parameters: parameters(
          { value: { $ref: "#/$defs/Shared" }, global: { $ref: "#/$defs/Global" } },
          { Shared: { type: "number" } },
        ),
      },
    },
  };
  const perResource = core.Catalog.fromSchema(catalog, "0.9");
  assert.equal(
    perResource.functions.get("text").schema.safeParse({ value: "ok", global: true }).success,
    true,
  );
  assert.equal(
    perResource.functions.get("text").schema.safeParse({ value: 42, global: true }).success,
    false,
  );
  assert.equal(
    perResource.functions.get("number").schema.safeParse({ value: 42, global: false }).success,
    true,
  );
  assert.equal(
    perResource.functions.get("number").schema.safeParse({ value: "bad", global: false }).success,
    false,
  );
  if (fixtureVersion === "0.12.0") {
    const recursive = load(
      { Shared: { type: "string" }, GlobalAlias: { $ref: "#/$defs/Shared" } },
      parameters(
        { entry: { $ref: "#/$defs/Node" } },
        {
          Shared: { type: "number" },
          Node: {
            type: "object",
            properties: {
              local: { $ref: "#/$defs/Shared" },
              global: { $ref: "#/$defs/GlobalAlias" },
              children: { type: "array", items: { $ref: "#/$defs/Node" } },
            },
            required: ["local", "global"],
          },
        },
      ),
    );
    assert.equal(
      recursive.safeParse({
        entry: { local: 1, global: "ok", children: [{ local: 2, global: "nested" }] },
      }).success,
      true,
      "lazy recursion retains both document contexts",
    );
    assert.equal(
      recursive.safeParse({
        entry: { local: 1, global: "ok", children: [{ local: 2, global: 42 }] },
      }).success,
      false,
    );
    const missing = load(
      {},
      parameters({ value: { $ref: "#/$defs/Missing" } }, { Unused: { type: "string" } }),
    );
    assert.equal(
      missing.safeParse({ value: "bad" }).success,
      false,
      "unresolved reference remains fail closed",
    );
    const localFalse = load(
      { Shared: { type: "string" } },
      parameters({ value: { $ref: "#/$defs/Shared" } }, { Shared: false }),
    );
    assert.equal(
      localFalse.safeParse({ value: "bad" }).success,
      false,
      "unsupported present local target does not fall back to permissive global target",
    );
  }
  return {
    publishedGlobalGuard: "preserved",
    mixedLocalGlobal: "passed",
    nestedGlobalContext: "passed",
    localPriority: "passed",
    perResourceCache: "passed",
    sharedInputNonmutation: "passed",
    lazyGlobalContext:
      fixtureVersion === "0.12.0" ? "passed" : "inherited-0.11-coarsening-not-expanded",
  };
}
function checkFunctionParameterResources(core, z, fixtureVersion, generateCatalogSchema) {
  const tree = z.lazy(() => z.object({ label: z.string(), children: z.array(tree).optional() }));
  const shared = z.enum(["a", "b"]);
  const fn = {
    name: "check/~",
    schema: z.object({ tree, labels: z.array(shared) }),
    returnType: "boolean",
  };
  const source =
    fixtureVersion === "0.11.0"
      ? new core.Catalog("parameter-fixture", [], [fn])
      : new core.Catalog("parameter-fixture", "0.9", [], [fn]);
  const emitted =
    fixtureVersion === "0.11.0"
      ? new core.MessageProcessor([source]).getClientCapabilities({ includeInlineCatalogs: true })[
          "v0.9"
        ].inlineCatalogs[0]
      : generateCatalogSchema(source);
  if (fixtureVersion === "0.11.0") {
    assert.ok(
      emitted.functions[0].parameters.$defs,
      "actual advertised function owns local definitions",
    );
  }
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
// Trusted, bounded fixture code installs the eval guard in the same global realm
// used by actual package imports. It never evaluates application-provided strings.
const evalGuard = runInThisContext(
  `(() => {
    const originalEval = globalThis.eval;
    let attempts = 0;
    globalThis.eval = function () {
      attempts++;
      throw new Error("synthetic strict CSP denies eval");
    };
    return {
      get attempts() { return attempts; },
      isSameGlobal(candidate) { return candidate === globalThis; },
      restore() { globalThis.eval = originalEval; }
    };
  })()`,
  { timeout: 1000, filename: "a2ui-csp-eval-guard.fixture.js" },
);
globalThis.Function = function () {
  compilationAttempts++;
  throw new Error("synthetic strict CSP denies Function");
};
try {
  assert.equal(
    evalGuard.isSameGlobal(globalThis),
    true,
    "eval guard shares actual package globals",
  );
  const core = await import(coreEntry);
  const lit = await import(pathToFileURL(projectRequire.resolve("@a2ui/lit/v0_9")));
  const { z } = await import(new URL("../common/zod-runtime.js", coreEntry));
  const require = createRequire(coreEntry);
  assert.equal(require("zod/package.json").version, "4.6.6");
  assert.equal(z.config().jitless, true);
  let visited = 0;
  const boundedChild = z.string().superRefine(() => {
    visited++;
  });
  assert.equal(z.array(boundedChild).max(1).safeParse(["a", "b"]).success, false);
  assert.equal(visited, 0);
  for (const name of [
    "A2uiController",
    "A2uiLitElement",
    "A2uiSurface",
    "Context",
    "basicCatalog",
  ]) {
    assert.ok(lit[name], name);
  }
  const basicProcessor = new core.MessageProcessor([lit.basicCatalog]);
  const basicCaps = basicProcessor.getClientCapabilities({
    versions: ["v0.9"],
    version: "v0.9",
    includeInlineCatalogs: true,
  });
  assert.equal(Object.keys(basicCaps["v0.9"].inlineCatalogs[0].components).length, 18);
  assert.equal(lit.basicCatalog.functions.size, version === "0.11.0" ? 25 : 14);
  const actions = [];
  const surface = new core.SurfaceModel("fixture", lit.basicCatalog);
  const bindingSchema = z.object({ label: core.CommonSchemas.DynamicString });
  const boundComponent = new core.ComponentModel(
    "c1",
    "Fixture",
    { label: { path: "/title" } },
    lit.basicCatalog,
  );
  surface.componentsModel.addComponent(boundComponent);
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
      if (this.controller?.props.label === "after") {
        onChangedUpdate?.();
      }
    },
  };
  const controller = new lit.A2uiController(host, { name: "Fixture", schema: bindingSchema });
  assert.equal(controller.props.label, "before");
  const changedUpdate = new Promise((resolve) => {
    onChangedUpdate = resolve;
  });
  surface.dataModel.set("/title", "after");
  await changedUpdate;
  assert.equal(controller.props.label, "after");
  assert.ok(actions.length > 0);
  controller.dispose();
  const legacyMessageSchemas = await import(
    new URL("../v0_8/schema/server-to-client.js", coreEntry)
  );
  assert.equal(typeof legacyMessageSchemas.A2uiMessageSchema.safeParse, "function");
  assert.equal(legacyMessageSchemas.A2uiMessageSchema.safeParse({ bogus: true }).success, false);

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
    if (version === "0.12.0") {
      assert.deepEqual(
        [...core.getKnownSchemaKeys(preprocess)],
        ["child"],
        "preprocess function argument allowlist",
      );
    }
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
      const node = z.lazy(() =>
        z.object({ label: z.string(), children: z.array(node).optional() }),
      );
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
        for (const token of ref.slice(2).split("/")) {
          target = target[token.replaceAll("~1", "/").replaceAll("~0", "~")];
        }
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
    const recursive = z.lazy(() =>
      z.object({ value: z.string(), children: z.array(recursive).optional() }),
    );
    const recursiveJson = zodToJsonSchema(recursive, options);
    let refs = 0;
    function validateRefs(value) {
      if (!value || typeof value !== "object") {
        return;
      }
      if (typeof value.$ref === "string") {
        assert.ok(value.$ref.startsWith("#"));
        let cursor = recursiveJson;
        for (const token of value.$ref.slice(2).split("/").filter(Boolean)) {
          cursor = cursor[token.replaceAll("~1", "/").replaceAll("~0", "~")];
          assert.ok(cursor);
        }
        refs++;
      }
      for (const child of Object.values(value)) {
        validateRefs(child);
      }
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
  checkMixedReferenceContexts(core, version);
  checkOwnReferenceRoots(core);
  checkProtocolAliasPrecedence(core);
  checkComponentReferenceContexts(core, z, version);
  assert.equal(compilationAttempts, 0);
  assert.equal(evalGuard.attempts, 0, "native package never attempts eval");
  console.log(
    JSON.stringify({
      version,
      zod: "4.6.6",
      catalogComponents: 18,
      catalogFunctions: lit.basicCatalog.functions.size,
      litReactiveBinding: "passed",
      legacySchema: "passed",
      nativeBoundedCollection: "passed",
      strictCsp: {
        dynamicCompilationAvailable: false,
        compilationAttempts: compilationAttempts + evalGuard.attempts,
      },
      qualification: "package-level synthetic, no browser render or application image claim",
    }),
  );
} finally {
  globalThis.Function = originalFunction;
  evalGuard.restore();
}
