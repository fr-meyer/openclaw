// Run with `node --test <this-file>` after the package patch and lockfile repair.
// Uses installed code and synthetic data only; no provider, database or browser network.
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { dirname, join, resolve } from "node:path";
import { test } from "node:test";
import { pathToFileURL, fileURLToPath } from "node:url";
const require = createRequire(import.meta.url);
const packagePath = require.resolve("@discord/embedded-app-sdk/package.json", {
  paths: process.env.DISCORD_SDK_TEST_PROJECT
    ? [resolve(process.env.DISCORD_SDK_TEST_PROJECT)]
    : [
        dirname(fileURLToPath(import.meta.url)),
        process.cwd(),
        join(process.cwd(), "extensions/discord"),
      ],
});
const sdkDirectory = dirname(packagePath);
const packageRequire = createRequire(packagePath);
const auth = {
  access_token: "synthetic-token",
  user: { username: "fixture", discriminator: "0001", id: "fixture", public_flags: 0 },
  scopes: ["identify", "future-scope"],
  expires: "2030-01-01",
  application: { description: "fixture", id: "fixture", name: "fixture" },
};
const relationships = (size) => ({
  relationships: [
    {
      type: 1,
      user: { id: "fixture", username: "fixture", discriminator: "0001", flags: 0, bot: false },
      presence: { status: "online", activity: { name: "fixture", party: { size } } },
    },
  ],
});
for (const format of ["mjs", "cjs"]) {
  const load = async (name) =>
    format === "mjs"
      ? import(pathToFileURL(join(sdkDirectory, "output", `${name}.${format}`)).href)
      : require(join(sdkDirectory, "output", `${name}.${format}`));
  test(`Discord ${format}: real constructor, READY and Activity authorization flow`, async () => {
    assert.equal(typeof globalThis.window, "undefined");
    assert.equal(typeof globalThis.document, "undefined");
    const listeners = new Map();
    const sent = [];
    let refusal = false;
    const parent = {
      postMessage(tuple) {
        sent.push(tuple);
        if (tuple[0] !== 1) return;
        const frame = tuple[1];
        const data = refusal
          ? { code: 4000, message: "synthetic refusal" }
          : frame.cmd === "AUTHORIZE"
            ? { code: "synthetic-code" }
            : auth;
        queueMicrotask(() =>
          listeners.get("message")?.({
            origin: "https://discord.com",
            data: [
              1,
              {
                cmd: frame.cmd,
                nonce: frame.nonce,
                evt: refusal ? "ERROR" : null,
                data,
              },
            ],
          }),
        );
      },
    };
    globalThis.window = {
      location: {
        origin: "https://fixture.invalid",
        search: "?frame_id=frame&instance_id=instance&platform=desktop&custom_id=custom",
      },
      parent,
      addEventListener(name, callback) {
        listeners.set(name, callback);
      },
      removeEventListener(name, callback) {
        if (listeners.get(name) === callback) listeners.delete(name);
      },
    };
    globalThis.document = { referrer: "https://discord.com" };
    try {
      const { DiscordSDK } = await load("index");
      const sdk = new DiscordSDK("fixture", { disableConsoleLogOverride: true });
      assert.equal(sdk.customId, "custom");
      assert.equal(sdk.instanceId, "instance");
      assert.equal(sent[0][0], 0);
      const ready = sdk.ready();
      listeners.get("message")({
        origin: "https://discord.com",
        data: [
          1,
          {
            cmd: "DISPATCH",
            evt: "READY",
            nonce: null,
            data: { v: 1, config: { api_endpoint: "https://invalid.test", environment: "test" } },
          },
        ],
      });
      await ready;
      assert.deepEqual(
        await sdk.commands.authorize({
          client_id: "fixture",
          response_type: "code",
          state: "",
          prompt: "none",
          scope: ["identify"],
        }),
        { code: "synthetic-code" },
      );
      assert.deepEqual(await sdk.commands.authenticate({ access_token: "synthetic-token" }), {
        ...auth,
        scopes: ["identify", -1],
      });
      refusal = true;
      await assert.rejects(
        sdk.commands.authorize({ client_id: "fixture", scope: ["identify"] }),
        (error) => error.code === 4000 && error.message === "synthetic refusal",
      );
      sdk.close(1000, "synthetic cleanup");
      assert.equal(listeners.size, 0);
    } finally {
      delete globalThis.window;
      delete globalThis.document;
    }
  });
  test(`Discord ${format}: parser is the actual official native dependency`, async () => {
    const parser = await load("lib/zod/lib/index");
    const official =
      format === "cjs"
        ? packageRequire("zod")
        : await import(
            pathToFileURL(join(dirname(packageRequire.resolve("zod/package.json")), "index.js"))
              .href
          );
    assert.equal(packageRequire("zod/package.json").version, "4.6.6");
    assert.equal(parser.ZodType, official.ZodType);
    assert.equal(parser.ZodObject, official.ZodObject);
    const { Common } = await load("index");
    assert.ok(Common.ReceiveFramePayload._zod);
  });
  test(`Discord ${format}: generated bounded schema rejects before visiting excess items`, async () => {
    const { GetRelationshipsResponseSchema } = await load("generated/schemas");
    assert.deepEqual(
      GetRelationshipsResponseSchema.parse(relationships([1, 2])),
      relationships([1, 2]),
    );
    let itemReads = 0;
    const size = new Proxy([1, 2, 3], {
      get(target, key, receiver) {
        if (typeof key === "string" && /^(0|[1-9][0-9]*)$/.test(key)) itemReads++;
        return Reflect.get(target, key, receiver);
      },
    });
    const rejected = GetRelationshipsResponseSchema.safeParse(relationships(size));
    assert.equal(rejected.success, false);
    assert.equal(itemReads, 0);
    assert.ok(Array.isArray(rejected.error.issues));
  });
  test(`Discord ${format}: unsupported scopes, envelope omission and fallback contract`, async () => {
    const generated = await load("generated/schemas");
    const { Common, Responses } = await load("index");
    const { IncomingPayload } = await load("schema/index");
    const frame = { cmd: "AUTHORIZE", evt: null, nonce: "fixture" };
    assert.deepEqual(Common.ReceiveFramePayload.parse(frame), frame);
    assert.deepEqual(IncomingPayload.parse(frame), frame);
    assert.deepEqual(generated.AuthenticateResponseSchema.parse(auth), {
      ...auth,
      scopes: ["identify", -1],
    });
    assert.equal(Common.ScopesObject.identify, "identify");
    assert.equal(Common.ScopesObject.UNHANDLED, -1);
    assert.deepEqual(Responses.OpenExternalLinkResponse.parse({ opened: "future-response" }), {
      opened: null,
    });
    const invalid = Responses.AuthorizeResponse.safeParse({ code: false });
    assert.equal(invalid.success, false);
    assert.equal(invalid.error.name, "ZodError");
    assert.ok(Array.isArray(invalid.error.issues));
    assert.equal(Object.hasOwn(invalid.error, "errors"), false);
  });
  test(`Discord ${format}: SDKError identity and RPC compatibility retry are preserved`, async () => {
    const z = await load("lib/zod/lib/index");
    const { SDKError } = await load("error");
    const { commandFactory } = await load("utils/commandFactory");
    const factory = await load("utils/compatCommandFactory");
    const { RPCErrorCodes } = await load("Constants");
    const reject = new SDKError(999, "synthetic");
    const command = commandFactory(
      async () => {
        throw reject;
      },
      "AUTHORIZE",
      z.object({ code: z.string() }),
    );
    await assert.rejects(command({}), (error) => error === reject);
    const calls = [];
    const compatible = factory.default({
      cmd: "AUTHORIZE",
      response: z.object({ code: z.string() }),
      fallbackTransform: () => ({}),
      sendCommand: async (payload) => {
        calls.push(payload);
        if (payload.args.newField) throw new SDKError(RPCErrorCodes.INVALID_PAYLOAD);
        return { cmd: "AUTHORIZE", evt: null, nonce: "fixture", data: { code: "fixture" } };
      },
    });
    assert.deepEqual(await compatible({ newField: true }), { code: "fixture" });
    assert.deepEqual(
      calls.map((call) => call.args),
      [{ newField: true }, {}],
    );
    assert.equal(reject.name, "Discord SDK Error");
    assert.equal(reject.code, 999);
    assert.equal(reject.message, "synthetic");
  });
}
