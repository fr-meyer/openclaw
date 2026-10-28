import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import https from "node:https";
import { createRequire, syncBuiltinESMExports } from "node:module";
import net from "node:net";
import path from "node:path";
import test from "node:test";
import tls from "node:tls";
import { fileURLToPath, pathToFileURL } from "node:url";

// This file is run in its own secretless native-test child. Every message and
// schema below is synthetic; even an accidental provider/network path refuses.
let networkCalls = 0;
const forbidNetwork = () => {
  networkCalls++;
  throw new Error("network forbidden in synthetic dependency regression");
};
http.request = http.get = https.request = https.get = forbidNetwork;
net.connect = net.createConnection = tls.connect = forbidNetwork;
globalThis.fetch = forbidNetwork;
syncBuiltinESMExports();

const root = fileURLToPath(new URL("../", import.meta.url));
const rootRequire = createRequire(path.join(root, "package.json"));
const imapRequire = createRequire(path.join(root, "extensions/imap/package.json"));
const teamsRequire = createRequire(path.join(root, "extensions/msteams/package.json"));
const uiRequire = createRequire(path.join(root, "ui/package.json"));
const rendererRequire = createRequire(path.join(root, "packages/mermaid-renderer/package.json"));

// Resolve from the actual consuming parent, not a hoisted root substitute.
function packageContext(requireFromParent, name, entry = name) {
  const resolved = fs.realpathSync(requireFromParent.resolve(entry));
  for (let current = path.dirname(resolved); ; current = path.dirname(current)) {
    const manifestPath = path.join(current, "package.json");
    if (fs.existsSync(manifestPath)) {
      const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
      if (manifest.name === name) {
        return { manifest, require: createRequire(manifestPath), entry: resolved };
      }
    }
    assert.notEqual(path.dirname(current), current, `Missing installed parent ${name}`);
  }
}

const sdk = packageContext(
  rootRequire,
  "@modelcontextprotocol/sdk",
  "@modelcontextprotocol/sdk/validation/ajv-provider.js",
);
const ajv = packageContext(sdk.require, "ajv");
const uri = ajv.require("fast-uri");

test("the real MCP SDK/AJV parent resolves the fixed URI parser", () => {
  assert.equal(sdk.manifest.version, "1.32.0");
  assert.equal(ajv.manifest.version, "8.20.0");
  assert.equal(packageContext(ajv.require, "fast-uri").manifest.version, "4.2.3");
});

test("SDK external schema validation keeps local refs, formats and rejection semantics", () => {
  const { AjvJsonSchemaValidator } = rootRequire(
    "@modelcontextprotocol/sdk/validation/ajv-provider.js",
  );
  const owner = new AjvJsonSchemaValidator();
  const validate = owner.getValidator({
    $id: "https://schemas.synthetic.invalid/dependency.json",
    type: "object",
    definitions: { location: { type: "string", format: "uri" } },
    properties: { location: { $ref: "#/definitions/location" } },
    required: ["location"],
    additionalProperties: false,
  });
  const ordinary = { location: "https://synthetic.invalid/a?q=1" };
  assert.deepEqual(validate(ordinary), { valid: true, data: ordinary, errorMessage: undefined });
  for (const invalid of [{ location: 1 }, { location: "not a URI" }, {}, { ...ordinary, extra: 1 }]) {
    const rejected = validate(invalid);
    assert.equal(rejected.valid, false);
    assert.equal(rejected.data, undefined);
    assert.equal(typeof rejected.errorMessage, "string");
  }
});

test("AJV's actual URI parser does not activate encoded schemes or rewrite malformed hosts", () => {
  for (const encoded of ["%6Aavascript:synthetic", "%u006Aavascript:synthetic"]) {
    assert.equal(uri.normalize(encoded), encoded);
    assert.ok(uri.parse(encoded).error);
  }
  for (const malformed of ["http://a@b@synthetic.invalid/", "http://a\tb.synthetic.invalid/"]) {
    assert.ok(uri.parse(malformed).error);
    assert.equal(uri.normalize(malformed), malformed);
  }
  assert.equal(uri.normalize("https://SYNTHETIC.invalid/a"), "https://synthetic.invalid/a");
});

test("AJV's actual URI parser preserves relative identity and escapes suffix scheme delimiters", () => {
  assert.equal(uri.normalize("../fixture"), "../fixture");
  assert.equal(uri.normalize("a/../fixture"), "fixture");
  assert.equal(uri.equal("../fixture", "fixture"), false);
  const suffix = uri.serialize({ path: "javascript:synthetic" }, { reference: "suffix" });
  assert.equal(suffix, "javascript%3Asynthetic");
  assert.equal(uri.parse(suffix).scheme, undefined);
  assert.equal(uri.resolve("https://synthetic.invalid/a/b", "../fixture"), "https://synthetic.invalid/fixture");
});

const mailparser = packageContext(imapRequire, "mailparser");
const mailauth = packageContext(imapRequire, "mailauth");
const { simpleParser } = imapRequire("mailparser");
const { dkimVerify } = imapRequire("mailauth");
const addressCases = [
  ["nested comment", "Victim (x(y) <attacker@other.invalid>) <v@allowed.invalid>", "v@allowed.invalid"],
  ["group comment", "G: (a; <attacker@other.invalid>) <v@allowed.invalid>;", "v@allowed.invalid"],
  ["quoted angle", '<"a@other.invalid>"@allowed.invalid>', '"a@other.invalid>"@allowed.invalid'],
];

function flattenAddresses(addresses) {
  return addresses.flatMap((address) =>
    address.group ? flattenAddresses(address.group) : [address.address],
  );
}

test("both actual IMAP mail parents resolve the fixed address parser", () => {
  assert.equal(mailparser.manifest.version, "3.9.33");
  assert.equal(mailauth.manifest.version, "7.1.0");
  for (const parent of [mailparser, mailauth]) {
    assert.equal(packageContext(parent.require, "nodemailer").manifest.version, "10.1.4");
  }
});

for (const [name, from, expected] of addressCases) {
  test(`mailparser and mailauth retain the same synthetic author for ${name}`, async () => {
    const raw = Buffer.from(
      `From: ${from}\r\nTo: reader@allowed.invalid\r\nSubject: synthetic fixture\r\n\r\nfixture\r\n`,
    );
    const parsed = await simpleParser(raw);
    assert.deepEqual(flattenAddresses(parsed.from.value), [expected]);
    // dkimVerify is mailauth's public message parser used by authenticate. No
    // signature is present, and an unexpected DNS request fails this fixture.
    const authentication = await dkimVerify(raw, {
      resolver: async () => { throw new Error("DNS forbidden in unsigned synthetic fixture"); },
    });
    assert.equal(authentication.fromFields, 1);
    assert.deepEqual(authentication.headerFrom, [expected]);
  });
}

test("actual Express and Teams query parents preserve fixed comma serialization", () => {
  const apps = packageContext(teamsRequire, "@microsoft/teams.apps");
  const parents = [
    packageContext(rootRequire, "express"),
    packageContext(teamsRequire, "express"),
    packageContext(teamsRequire, "@microsoft/teams.api"),
    packageContext(apps.require, "@microsoft/teams.graph"),
  ];
  for (const parent of parents) {
    assert.equal(packageContext(parent.require, "qs").manifest.version, "6.16.1");
    const qs = parent.require("qs");
    assert.equal(qs.stringify({ ordinary: "fixture" }), "ordinary=fixture");
    let encoded;
    assert.doesNotThrow(() => {
      encoded = qs.stringify({ a: [{ toString: "synthetic" }] }, { arrayFormat: "comma" });
    });
    assert.equal(typeof encoded, "string");
  }
});

test("actual MCP rate-limit and IMAP SOCKS parents resolve fixed IPv6 validation", () => {
  const rateLimit = packageContext(sdk.require, "express-rate-limit");
  const imapflow = packageContext(imapRequire, "imapflow");
  const socks = packageContext(imapflow.require, "socks");
  for (const parent of [rateLimit, socks]) {
    assert.equal(packageContext(parent.require, "ip-address").manifest.version, "10.7.4");
    const { Address6 } = parent.require("ip-address");
    assert.equal(new Address6("2001:db8::1").correctForm(), "2001:db8::1");
    assert.equal(Address6.isValid("2001:db8::1"), true);
    assert.equal(Address6.isValid(`${"%".repeat(512)}\n`), false);
  }
  // This is bounded parser/parent compatibility, not a timing benchmark or
  // proof that these optional transport branches are reachable in production.
});

test("Mermaid's actual KaTeX child ignores inherited trust and retains ordinary rendering", () => {
  const mermaid = packageContext(rendererRequire, "mermaid");
  assert.equal(mermaid.manifest.version, "12.1.0");
  assert.equal(packageContext(mermaid.require, "katex").manifest.version, "0.18.2");
  const katex = mermaid.require("katex");
  assert.match(katex.renderToString("x^2 + y^2", { throwOnError: true }), /class="katex"/);
  const expression = "\\href{https://synthetic.invalid/fixture}{fixture}";
  const inheritedOptions = Object.assign(Object.create({ trust: true }), { throwOnError: false });
  assert.doesNotMatch(katex.renderToString(expression, inheritedOptions), /href=/);
  assert.match(katex.renderToString(expression, { trust: true, throwOnError: true }), /href=/);
  // Actual Mermaid rendering/sanitizer/CSP is exercised by the maintained UI
  // browser owners, not by this Node-side parent-resolution/API test.
});

test("the actual aligned Vitest mock generator treats hostile registration values as data", async () => {
  const vitest = packageContext(rootRequire, "vitest");
  const mocker = packageContext(vitest.require, "@vitest/mocker", "@vitest/mocker/node");
  assert.equal(vitest.manifest.version, "5.0.5");
  assert.equal(mocker.manifest.version, "5.0.5");
  assert.equal(packageContext(uiRequire, "@vitest/browser").manifest.version, "5.0.5");
  const { createManualModuleSource } = await import(pathToFileURL(mocker.entry).href);
  const maliciousUrl = 'fixture");globalThis.__v108DependencyInjection = true;//';
  const maliciousExport = 'fixture";globalThis.__v108DependencyInjection = true;//';
  const previous = Object.getOwnPropertyDescriptor(globalThis, "__vitest_mocker__");
  const previousMarker = Object.getOwnPropertyDescriptor(globalThis, "__v108DependencyInjection");
  const observed = [];
  try {
    delete globalThis.__v108DependencyInjection;
    globalThis.__vitest_mocker__ = {
      async getFactoryModule(url) {
        observed.push(url);
        return { ordinary: "synthetic", [maliciousExport]: "still data" };
      },
    };
    const code = createManualModuleSource(maliciousUrl, ["ordinary", maliciousExport]);
    const module = await import(`data:text/javascript;base64,${Buffer.from(code).toString("base64")}`);
    assert.deepEqual(observed, [maliciousUrl]);
    assert.equal(module.ordinary, "synthetic");
    assert.equal(module[maliciousExport], "still data");
    assert.equal(globalThis.__v108DependencyInjection, undefined);
  } finally {
    if (previous) Object.defineProperty(globalThis, "__vitest_mocker__", previous);
    else delete globalThis.__vitest_mocker__;
    if (previousMarker) Object.defineProperty(globalThis, "__v108DependencyInjection", previousMarker);
    else delete globalThis.__v108DependencyInjection;
  }
});

test("no real network operation occurred", () => assert.equal(networkCalls, 0));
