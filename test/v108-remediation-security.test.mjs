import assert from "node:assert/strict";
import { EventEmitter, once } from "node:events";
import fs from "node:fs";
import http from "node:http";
import https from "node:https";
import { createRequire, findPackageJSON, syncBuiltinESMExports } from "node:module";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { Writable } from "node:stream";
import test from "node:test";
import tls from "node:tls";
import { fileURLToPath, pathToFileURL } from "node:url";
import { runInNewContext } from "node:vm";
import { Worker } from "node:worker_threads";

// This file is run in its own secretless native-test child. Every message and
// schema below is synthetic; even an accidental provider/unowned network path refuses.
const ownedLoopbackHttpRequest = http.request;
const ownedLoopbackConnect = net.connect;
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

// Crabline exposes only its ESM entry. Locate metadata from the real consuming
// parent without requiring either its entry point or a package.json export.
function crablinePackageContext(parentRequire) {
  const manifestPath = findPackageJSON(
    "@openclaw/crabline",
    parentRequire.resolve("./package.json"),
  );
  assert.ok(typeof manifestPath === "string" && path.isAbsolute(manifestPath));
  const realManifestPath = fs.realpathSync(manifestPath);
  assert.equal(fs.statSync(realManifestPath).isFile(), true);
  const manifest = JSON.parse(fs.readFileSync(realManifestPath, "utf8"));
  assert.equal(manifest.name, "@openclaw/crabline");
  return { manifest, require: createRequire(realManifestPath) };
}

const sdk = packageContext(
  rootRequire,
  "@modelcontextprotocol/sdk",
  "@modelcontextprotocol/sdk/validation/ajv-provider.js",
);
const ajv = packageContext(sdk.require, "ajv");
const uri = ajv.require("fast-uri");

test("the real MCP SDK/AJV parent resolves the fixed URI parser", () => {
  assert.equal(sdk.manifest.version, "1.32.1");
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
  for (const invalid of [
    { location: 1 },
    { location: "not a URI" },
    {},
    { ...ordinary, extra: 1 },
  ]) {
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
  assert.equal(
    uri.resolve("https://synthetic.invalid/a/b", "../fixture"),
    "https://synthetic.invalid/fixture",
  );
});

const mailparser = packageContext(imapRequire, "mailparser");
const mailauth = packageContext(imapRequire, "mailauth");
const { simpleParser } = imapRequire("mailparser");
const { dkimVerify } = imapRequire("mailauth");
const addressCases = [
  [
    "nested comment",
    "Victim (x(y) <attacker@other.invalid>) <v@allowed.invalid>",
    "v@allowed.invalid",
  ],
  ["group comment", "G: (a; <attacker@other.invalid>) <v@allowed.invalid>;", "v@allowed.invalid"],
  ["quoted angle", '<"a@other.invalid>"@allowed.invalid>', '"a@other.invalid>"@allowed.invalid'],
];

function flattenAddresses(addresses) {
  return addresses.flatMap((address) =>
    address.group ? flattenAddresses(address.group) : [address.address],
  );
}

test("both actual IMAP mail parents resolve the fixed address parser", () => {
  assert.equal(mailparser.manifest.version, "3.9.36");
  assert.equal(mailauth.manifest.version, "7.1.1");
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
      resolver: async () => {
        throw new Error("DNS forbidden in unsigned synthetic fixture");
      },
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
    const module = await import(
      `data:text/javascript;base64,${Buffer.from(code).toString("base64")}`
    );
    assert.deepEqual(observed, [maliciousUrl]);
    assert.equal(module.ordinary, "synthetic");
    assert.equal(module[maliciousExport], "still data");
    assert.equal(globalThis.__v108DependencyInjection, undefined);
  } finally {
    if (previous) Object.defineProperty(globalThis, "__vitest_mocker__", previous);
    else delete globalThis.__vitest_mocker__;
    if (previousMarker)
      Object.defineProperty(globalThis, "__v108DependencyInjection", previousMarker);
    else delete globalThis.__v108DependencyInjection;
  }
});

// GHSA-gg6h-894w-4m9c: exercise the installed child through both consuming
// parents. The fixed public fixtures are pinned to RE2JS release 6ba840014b19,
// stability.test.js:78-122 and Lookbehind.test.js:220-268. This is bounded API
// correctness/completion, not an internal Machine.step or universal latency proof.
const re2jsRegressionWorker = String.raw`
  const { parentPort, workerData } = require("node:worker_threads");
  const { pathToFileURL } = require("node:url");
  const { isAbsolute } = require("node:path");
  const { syncBuiltinESMExports } = require("node:module");
  let networkCalls = 0;
  const denyNetwork = () => {
    networkCalls++;
    throw new Error("network forbidden in isolated RE2JS regression");
  };
  for (const name of ["node:http", "node:https"]) {
    const owner = require(name);
    owner.request = owner.get = denyNetwork;
  }
  const net = require("node:net");
  net.connect = net.createConnection = denyNetwork;
  require("node:tls").connect = denyNetwork;
  globalThis.fetch = denyNetwork;
  syncBuiltinESMExports();
  let phase = "initialization";
  const check = (value) => {
    if (!value) throw new Error("RE2JS regression refused");
  };
  (async () => {
    check(workerData && Object.keys(workerData).join(",") === "entries");
    const entries = workerData.entries;
    check(Array.isArray(entries) && entries.length >= 1 && entries.length <= 4);
    let checks = 0;
    for (const entry of entries) {
      check(entry && Object.keys(entry).sort().join(",") === "format,path");
      check((entry.format === "import" || entry.format === "require") &&
        typeof entry.path === "string" && isAbsolute(entry.path));
      phase = "import";
      const api = entry.format === "import"
        ? await import(pathToFileURL(entry.path).href)
        : require(entry.path);
      const { RE2JS } = api;
      check(typeof RE2JS?.compile === "function" && Number.isInteger(RE2JS.LOOKBEHINDS));
      const repeatCount = 8000;
      const input = "ab".repeat(repeatCount);
      check(input.length === 16000);
      const pattern = RE2JS.compile("(?<=a)b", RE2JS.LOOKBEHINDS);
      phase = "find";
      const matcher = pattern.matcher(input);
      let found = 0;
      while (matcher.find()) {
        found++;
        check(found <= repeatCount);
      }
      check(found === repeatCount);
      checks++;
      phase = "matchAll";
      let matched = 0;
      let lastIndex = -1;
      for (const match of pattern.matchAll(input)) {
        matched++;
        check(matched <= repeatCount);
        lastIndex = match.index;
      }
      check(matched === repeatCount && lastIndex === input.length - 1);
      checks++;
      phase = "split";
      const parts = pattern.split(input);
      check(parts.length >= repeatCount && parts.length <= input.length + 1 && parts[0] === "a");
      checks++;
      phase = "replaceAll";
      check(pattern.matcher(input).replaceAll("X") === "aX".repeat(repeatCount));
      checks++;
      phase = "backward";
      const backward = pattern.matcher("ab".repeat(5));
      for (const [start, expected] of [[0, 1], [4, 5], [9, 9], [2, 3]]) {
        check(backward.find(start) === true && backward.start() === expected);
      }
      check(backward.find(10) === false);
      checks++;
      phase = "newInput";
      const replacedInput = RE2JS.compile("(?<=x.*)b", RE2JS.LOOKBEHINDS).matcher("xab ab");
      check(replacedInput.find() === true && replacedInput.find() === true && replacedInput.find() === false);
      replacedInput.resetMatcherInput("ab ab");
      check(replacedInput.find() === false);
      replacedInput.resetMatcherInput("ab xab");
      check(replacedInput.find() === true && replacedInput.start() === 5 && replacedInput.find() === false);
      checks++;
      phase = "reset";
      const reset = RE2JS.compile("(?<!x)ab", RE2JS.LOOKBEHINDS).matcher("abab");
      check(reset.find() === true && reset.start() === 0);
      check(reset.find() === true && reset.start() === 2 && reset.find() === false);
      check(reset.lookingAt() === true && reset.end() === 2 && reset.matches() === false);
      reset.reset();
      check(reset.find() === true && reset.start() === 0);
      checks++;
    }
    check(networkCalls === 0);
    parentPort.postMessage({ schema: "re2js-regression-v1", ok: true, phase: "complete",
      entries: entries.length, checks, networkCalls });
  })().catch(() => {
    parentPort.postMessage({ schema: "re2js-regression-v1", ok: false, phase });
    process.exitCode = 1;
  });
`;

async function runOwnedRe2jsWorker(entries, signal) {
  signal.throwIfAborted();
  const worker = new Worker(re2jsRegressionWorker, {
    eval: true,
    execArgv: [],
    workerData: { entries },
    env: {
      NODE_ENV: "test",
      HOME: "/nonexistent",
      USERPROFILE: "/nonexistent",
      LANG: "C",
      LC_ALL: "C",
    },
    resourceLimits: { maxOldGenerationSizeMb: 128, maxYoungGenerationSizeMb: 16, stackSizeMb: 4 },
  });
  let timedOut = false;
  let aborted = false;
  let failed = false;
  let duplicate = false;
  let messages = 0;
  let report;
  let termination;
  const stop = () => {
    termination ??= worker.terminate().then(
      () => true,
      () => false,
    );
  };
  const onAbort = () => {
    aborted = true;
    stop();
  };
  signal.addEventListener("abort", onAbort, { once: true });
  // A real parent deadline is essential here: the algorithm under test may
  // block its worker's event loop. Exit/termination, not this timer, settles it.
  const timer = setTimeout(() => {
    timedOut = true;
    stop();
  }, 20_000);
  if (signal.aborted) onAbort();
  return new Promise((resolve, reject) => {
    worker.on("message", (message) => {
      if (++messages !== 1) duplicate = true;
      else report = message;
    });
    worker.once("error", () => {
      failed = true;
    });
    worker.once("exit", async (code) => {
      clearTimeout(timer);
      signal.removeEventListener("abort", onAbort);
      const settled = termination === undefined || (await termination);
      if (timedOut || aborted || failed || duplicate || code !== 0 || !settled) {
        reject(new Error("isolated RE2JS worker failed or exceeded its owned deadline"));
      } else {
        resolve(report);
      }
    });
  });
}

test(
  "the actual Crabline parents use fixed RE2JS lookbehind behavior in an isolated worker",
  {
    timeout: 30_000,
  },
  async (t) => {
    const qaLabRequire = createRequire(path.join(root, "extensions/qa-lab/package.json"));
    const entries = new Map();
    for (const parentRequire of [rootRequire, qaLabRequire]) {
      const crabline = crablinePackageContext(parentRequire);
      assert.equal(crabline.manifest.version, "0.1.29");
      const child = packageContext(crabline.require, "re2js");
      assert.equal(child.manifest.version, "2.8.7");
      const exports = child.manifest.exports?.["."];
      assert.equal(exports?.require?.default, "./build/index.cjs");
      assert.equal(exports?.import?.default, "./build/index.js");
      const packageRoot = path.dirname(child.require.resolve("./package.json"));
      for (const [format, relative] of [
        ["require", exports.require.default],
        ["import", exports.import.default],
      ]) {
        const entry = fs.realpathSync(path.join(packageRoot, relative));
        assert.equal(entry.startsWith(fs.realpathSync(packageRoot) + path.sep), true);
        if (format === "require") assert.equal(entry, child.entry);
        entries.set(`${format}:${entry}`, { format, path: entry });
      }
    }
    assert.ok(entries.size >= 2 && entries.size <= 4);
    const startedAt = performance.now();
    const report = await runOwnedRe2jsWorker([...entries.values()], t.signal);
    assert.deepEqual(Object.keys(report).sort(), [
      "checks",
      "entries",
      "networkCalls",
      "ok",
      "phase",
      "schema",
    ]);
    assert.equal(report.schema, "re2js-regression-v1");
    assert.equal(report.ok, true);
    assert.equal(report.phase, "complete");
    assert.equal(report.entries, entries.size);
    assert.equal(report.checks, entries.size * 7);
    assert.equal(report.networkCalls, 0);
    assert.equal(networkCalls, 0);
    t.diagnostic(
      `isolated RE2JS API/state checks completed in ${Math.round(performance.now() - startedAt)}ms`,
    );
  },
);

// These H3 fixtures use the public package APIs from the same installed parents
// selected by OpenClaw. They do not claim optional production routes are enabled.
const fileTransferRequire = createRequire(path.join(root, "extensions/file-transfer/package.json"));
const feishuRequire = createRequire(path.join(root, "extensions/feishu/package.json"));
const h3MatcherParents = [rootRequire, fileTransferRequire].map((parent) => ({
  context: packageContext(parent, "minimatch"),
  api: parent("minimatch"),
}));
const h3JoiContext = packageContext(mailauth.require, "joi");
const h3Joi = mailauth.require("joi");
const h3Sigstore = packageContext(rootRequire, "sigstore");
const h3Signer = packageContext(h3Sigstore.require, "@sigstore/sign");
const h3MakeFetch = packageContext(h3Signer.require, "make-fetch-happen");
const h3Cache = packageContext(h3MakeFetch.require, "cacache");
const h3GlobContext = packageContext(h3Cache.require, "glob");
const h3HttpParents = [
  packageContext(feishuRequire, "@larksuiteoapi/node-sdk"),
  packageContext(teamsRequire, "@microsoft/teams.apps"),
  packageContext(
    packageContext(teamsRequire, "@microsoft/teams.api").require,
    "@microsoft/teams.common",
  ),
].map((parent) => {
  const axios = packageContext(parent.require, "axios");
  return { axios, child: packageContext(axios.require, "follow-redirects") };
});

test("the actual retained HTTP, mail, matcher and cache parents resolve the four H3 fixes", () => {
  for (const { context } of h3MatcherParents) assert.equal(context.manifest.version, "11.0.1");
  assert.equal(h3JoiContext.manifest.version, "18.3.1");
  assert.equal(h3Cache.manifest.version, "21.0.1");
  assert.equal(h3GlobContext.manifest.version, "14.0.2");
  for (const { axios, child } of h3HttpParents) {
    assert.equal(axios.manifest.version, "1.20.0");
    assert.equal(child.manifest.version, "1.16.2");
  }
});

test("both installed matchers preserve bootstrap, transfer and service path semantics", () => {
  for (const { api } of h3MatcherParents) {
    const { minimatch, escape } = api;
    const bootstrap = { nocomment: true, nonegate: true, windowsPathsNoEscape: true };
    assert.equal(minimatch("src/fixture.ts", "src/**/*.ts", bootstrap), true);
    assert.equal(minimatch("other/fixture.ts", "src/**/*.ts", bootstrap), false);
    assert.equal(minimatch("!fixture.txt", "!fixture.txt", bootstrap), true);
    assert.equal(
      minimatch("C:/fixture/private.txt", "C:/fixture/*.txt", { ...bootstrap, platform: "win32" }),
      true,
    );
    assert.equal(
      minimatch("C:/other/private.txt", "C:/fixture/*.txt", { ...bootstrap, platform: "win32" }),
      false,
    );
    assert.equal(minimatch("nested/.fixture", "**/*", { dot: true }), true);
    assert.equal(minimatch("nested/.fixture", "**/*.txt", { dot: true }), false);
    assert.equal(minimatch("a/fixture.ts", "{a,b}/**/*.ts", { dot: true }), true);
    assert.equal(minimatch("c/fixture.ts", "{a,b}/**/*.ts", { dot: true }), false);
    const literal = "[synthetic]*?.env";
    assert.equal(minimatch(literal, escape(literal), { optimizationLevel: 0 }), true);
    assert.equal(minimatch("ordinary.env", escape(literal), { optimizationLevel: 0 }), false);
  }
});

test("the installed matcher bounds parent-segment expansion without changing matches", () => {
  for (const { api } of h3MatcherParents) {
    const { Minimatch } = api;
    // Ten segments remain bounded even on the pre-fix package, while exceeding
    // the explicit limit proves the affected preprocessing contract.
    const expanded = new Minimatch(Array(10).fill("**/../a/b").join("/"), {
      optimizationLevel: 2,
      braceExpandMax: 64,
    });
    assert.equal(expanded.set.length, 64);
    const ordinary = new Minimatch("**/../a/b/**/../c/d", { optimizationLevel: 2 });
    assert.equal(ordinary.match("../a/b/../c/d"), true);
    assert.equal(ordinary.match("x/a/b/y/c/d"), true);
    // This exercises the >1000-pattern branch with only 1002 bounded patterns.
    const large = new Minimatch("{x,*}/{0..500}", { optimizationLevel: 2 });
    assert.equal(large.set.length, 1002);
    assert.equal(large.match("x/5"), true);
    assert.equal(large.match("y/500"), true);
    assert.equal(large.match(".y/5"), false);
  }
});

test("mailauth's installed Joi preserves multiple-email separation and malformed-input rejection", () => {
  assert.equal(h3Joi.string().email().validate("first@example.com").error, undefined);
  assert.equal(
    h3Joi.string().email({ multiple: true }).validate("first@example.com, second@example.org")
      .error,
    undefined,
  );
  assert.equal(
    h3Joi
      .string()
      .email({ multiple: true, separator: ";" })
      .validate("first@example.com; second@example.org").error,
    undefined,
  );
  const spaces = " ".repeat(1024);
  const mixed = `first@example.com${spaces}second@example.org`;
  for (const [options, input, expectedInvalids] of [
    [{}, spaces, [spaces]],
    [{ separator: ";" }, mixed, [mixed]],
    [{ separator: ", " }, spaces, ["", ""]],
  ]) {
    const { error } = h3Joi
      .string()
      .email({ multiple: true, ...options })
      .validate(input);
    assert.ok(error, "malformed synthetic address list must be rejected");
    assert.equal(error.details[0].type, "string.email");
    assert.deepEqual(error.details[0].context.invalids, expectedInvalids);
  }
  assert.equal(
    h3Joi.string().email({ multiple: true, separator: ", " }).validate(mixed).error,
    undefined,
  );
  // Bounded API correctness only; no universal latency/asymptotic claim.
});

test("mailauth's Joi rejects prototype message languages and preserves existing rename targets", () => {
  const messages = JSON.parse('{"__proto__":{"number.min":"SYNTHETIC_H3_MESSAGE"}}');
  const baseline = Object.getOwnPropertyDescriptor(Object.prototype, "number.min");
  try {
    for (const invoke of [
      () => h3Joi.number().min(10).messages(messages),
      () => h3Joi.number().min(10).prefs({ messages }),
      () => h3Joi.number().min(10).validate(1, { messages }),
    ])
      assert.throws(invoke, /Cannot use __proto__ as a language/);
    assert.deepEqual(h3Joi.object().rename("a", "toString").unknown().validate({ a: 1 }), {
      value: { toString: 1 },
    });
    for (const [schema, input, target] of [
      [
        h3Joi.object().rename("a", "constructor", { multiple: true }).unknown(),
        { a: "synthetic", constructor: "original" },
        "constructor",
      ],
      [
        h3Joi
          .object()
          .rename(/^k_(.*)$/, h3Joi.expression("{#1}"), { multiple: true })
          .unknown(),
        { k_hasOwnProperty: "synthetic", hasOwnProperty: "original" },
        "hasOwnProperty",
      ],
    ]) {
      const result = schema.validate(input);
      assert.ok(result.error, "an existing synthetic target must not be overwritten");
      assert.equal(result.error.details[0].type, "object.rename.override");
      assert.equal(result.value[target], "original");
    }
    assert.deepEqual(Object.getOwnPropertyDescriptor(Object.prototype, "number.min"), baseline);
  } finally {
    if (baseline) Object.defineProperty(Object.prototype, "number.min", baseline);
    else delete Object.prototype["number.min"];
  }
});

test(
  "real redirect handling strips cross-realm sensitive headers between owned origins",
  {
    timeout: 10_000,
  },
  async (t) => {
    const received = [];
    const ownedPorts = new Set();
    let target;
    let redirect;
    const previousRequest = http.request;
    async function listenOwned(server) {
      const listening = once(server, "listening", { signal: t.signal });
      server.listen({ host: "127.0.0.1", port: 0, signal: t.signal });
      await listening;
      const address = server.address();
      assert.equal(address.address, "127.0.0.1");
      ownedPorts.add(address.port);
      return address.port;
    }
    try {
      target = http.createServer((request, response) => {
        received.push({
          secret: request.headers["x-synthetic-secret"],
          authorization: request.headers.authorization,
          kept: request.headers["x-synthetic-kept"],
        });
        response.end("SYNTHETIC_H3_TARGET");
      });
      const targetPort = await listenOwned(target);
      redirect = http.createServer((_request, response) => {
        response.writeHead(302, { location: `http://127.0.0.1:${targetPort}/target` });
        response.end();
      });
      const redirectPort = await listenOwned(redirect);
      // The global denial remains for HTTPS, DNS and every unowned destination.
      // Only these two servers can be reached through the captured native socket.
      http.request = (options, callback) => {
        assert.equal(options.protocol, "http:");
        assert.equal(options.hostname, "127.0.0.1");
        assert.equal(options.socketPath, undefined);
        assert.equal(ownedPorts.has(Number(options.port)), true);
        return ownedLoopbackHttpRequest(
          {
            ...options,
            agent: undefined,
            createConnection: () =>
              ownedLoopbackConnect({ host: "127.0.0.1", port: Number(options.port) }),
          },
          callback,
        );
      };
      syncBuiltinESMExports();
      const entries = new Map(
        h3HttpParents.map(({ axios, child }) => [child.entry, axios.require("follow-redirects")]),
      );
      for (const api of entries.values()) {
        for (const sensitiveHeaders of [
          ["x-synthetic-secret"],
          runInNewContext('["x-synthetic-secret"]'),
        ]) {
          assert.equal(Array.isArray(sensitiveHeaders), true);
          await new Promise((resolve, reject) => {
            const request = api.http.get(
              {
                hostname: "127.0.0.1",
                port: redirectPort,
                path: "/redirect",
                signal: t.signal,
                sensitiveHeaders,
                headers: {
                  authorization: "SYNTHETIC_AUTH",
                  "x-synthetic-secret": "SYNTHETIC_SECRET",
                  "x-synthetic-kept": "retained",
                },
              },
              (response) => {
                const chunks = [];
                let bytes = 0;
                response.on("data", (chunk) => {
                  bytes += chunk.length;
                  if (bytes > 1024)
                    response.destroy(new Error("bounded synthetic redirect body exceeded"));
                  else chunks.push(chunk);
                });
                response.on("error", reject);
                response.on("end", () => {
                  try {
                    assert.equal(response.statusCode, 200);
                    assert.equal(Buffer.concat(chunks).toString("utf8"), "SYNTHETIC_H3_TARGET");
                    resolve();
                  } catch (error) {
                    reject(error);
                  }
                });
              },
            );
            request.on("error", reject);
          });
        }
      }
      assert.equal(received.length, entries.size * 2);
      for (const observed of received) {
        assert.deepEqual(observed, {
          secret: undefined,
          authorization: undefined,
          kept: "retained",
        });
      }
      assert.equal(networkCalls, 0);
    } finally {
      try {
        const closing = [];
        for (const server of [redirect, target]) {
          if (server) {
            server.closeAllConnections();
            closing.push(
              new Promise((resolve, reject) =>
                server.close((error) =>
                  error && error.code !== "ERR_SERVER_NOT_RUNNING" ? reject(error) : resolve(),
                ),
              ),
            );
          }
        }
        const outcomes = await Promise.allSettled(closing);
        for (const outcome of outcomes) if (outcome.status === "rejected") throw outcome.reason;
      } finally {
        http.request = previousRequest;
        syncBuiltinESMExports();
      }
    }
  },
);

test(
  "the real cache keeps content across verification and its glob stops at aborted reads",
  {
    timeout: 10_000,
  },
  async (t) => {
    const cache = h3MakeFetch.require("cacache");
    const { glob, globSync, globStreamSync } = h3Cache.require("glob");
    // openclaw-temp-dir: allow owns an external dependency filesystem adapter and cleanup.
    const fixture = fs.mkdtempSync(path.join(os.tmpdir(), "v109-glob-cache-"));
    try {
      const walkRoot = path.join(fixture, "walk");
      for (const relative of ["a/one.txt", "a/b/two.txt", "c/three.txt", "c/d/ignored.bin"]) {
        const file = path.join(walkRoot, relative);
        fs.mkdirSync(path.dirname(file), { recursive: true });
        fs.writeFileSync(file, "SYNTHETIC_H3_FILE");
      }
      assert.deepEqual(globSync("**/*.txt", { cwd: walkRoot, nodir: true }).sort(), [
        "a/b/two.txt",
        "a/one.txt",
        "c/three.txt",
      ]);
      const cacheRoot = path.join(fixture, "cache");
      const payload = Buffer.from("SYNTHETIC_H3_CACHE_PAYLOAD");
      await cache.put(cacheRoot, "synthetic-key", payload);
      await cache.verify(cacheRoot);
      assert.deepEqual((await cache.get(cacheRoot, "synthetic-key")).data, payload);

      const aborted = new Error("SYNTHETIC_H3_ABORT");
      const asyncController = new AbortController();
      const asyncReads = new EventEmitter();
      const firstRead = once(asyncReads, "read", { signal: t.signal });
      const pending = [];
      let asyncCount = 0;
      const ownedDirectory = (directory) => {
        assert.equal(typeof directory, "string");
        const resolved = path.resolve(directory);
        assert.equal(resolved === walkRoot || resolved.startsWith(walkRoot + path.sep), true);
      };
      const asyncFs = {
        ...fs,
        readdir(directory, options, callback) {
          if (typeof options === "function") {
            callback = options;
            options = undefined;
          }
          assert.equal(typeof callback, "function");
          ownedDirectory(directory);
          asyncCount++;
          assert.equal(asyncCount, 1, "no directory read may begin after the owned abort");
          pending.push((error) =>
            error ? callback(error) : callback(null, fs.readdirSync(directory, options)),
          );
          if (asyncCount === 1) {
            asyncController.abort(aborted);
            asyncReads.emit("read");
          }
        },
      };
      const walking = glob("**", { cwd: walkRoot, signal: asyncController.signal, fs: asyncFs });
      const rejected = assert.rejects(walking, (error) => error === aborted);
      try {
        await Promise.race([firstRead, rejected]);
        // Release actual directory data only after abort. The callbacks are owned
        // fixture work, not sleeps or a predicted traversal result.
        let delivered = 0;
        while (pending.length) {
          assert.ok(++delivered <= 32, "bounded synthetic traversal callbacks");
          pending.shift()();
        }
        await rejected;
        assert.equal(asyncCount, 1);
        assert.equal(pending.length, 0);
      } finally {
        asyncController.abort(aborted);
        while (pending.length) pending.shift()(aborted);
        await rejected;
      }

      const syncController = new AbortController();
      let syncCount = 0;
      const syncFs = {
        ...fs,
        readdirSync(directory, options) {
          ownedDirectory(directory);
          if (++syncCount === 1) syncController.abort(aborted);
          return fs.readdirSync(directory, options);
        },
      };
      const stream = globStreamSync("**", {
        cwd: walkRoot,
        signal: syncController.signal,
        fs: syncFs,
      });
      const error = once(stream, "error", { signal: t.signal });
      try {
        stream.resume();
        assert.equal((await error)[0], aborted);
        assert.equal(syncCount, 1);
      } finally {
        stream.destroy();
      }
      assert.equal(networkCalls, 0);
    } finally {
      fs.rmSync(fixture, { recursive: true, force: true });
    }
  },
);

test("no unowned network operation occurred", () => assert.equal(networkCalls, 0));

test(
  "actual Vitest API-mode HTTP denies synthetic private files and its token",
  {
    timeout: 45_000,
    skip: process.platform !== "linux" && "Linux CI-only: fixture owns the XDG API-token path",
  },
  async (t) => {
    // openclaw-temp-dir: allow owns an external-tool HTTP fixture and its HOME.
    const fixture = fs.mkdtempSync(path.join(os.tmpdir(), "v108-vitest-http-"));
    const served = path.join(fixture, "served");
    const home = path.join(fixture, "home");
    const ownedEnvironment = {
      HOME: home,
      USERPROFILE: home,
      XDG_CONFIG_HOME: path.join(home, "config"),
      XDG_CACHE_HOME: path.join(home, "cache"),
      XDG_DATA_HOME: path.join(served, "data"),
    };
    const previousEnvironment = Object.fromEntries(
      Object.keys(ownedEnvironment).map((key) => [key, process.env[key]]),
    );
    const markers = new Map([
      [".env", "SYNTHETIC_V108_ENV_MARKER"],
      [".env.production", "SYNTHETIC_V108_ENV_VARIANT_MARKER"],
      [".npmrc", "SYNTHETIC_V108_NPMRC_MARKER"],
      [".git/config", "SYNTHETIC_V108_GIT_MARKER"],
      ["fixture.pem", "SYNTHETIC_V108_KEY_MARKER"],
      ["data/vitest/.vitest-secret-token", "SYNTHETIC_V108_API_TOKEN_MARKER"],
    ]);
    const files = new Map(
      [...markers].map(([relative, marker]) => [path.join(served, relative), marker]),
    );
    const publicFile = path.join(served, "allowed.txt");
    const allowedPaths = new Set([publicFile, ...files.keys()]);
    let context;
    let server;
    let ownedPort;
    const silent = new Writable({
      write(_chunk, _encoding, done) {
        done();
      },
    });
    async function getOwnedFile(file, suffix = "") {
      assert.equal(allowedPaths.has(file), true);
      assert.ok(suffix === "" || suffix === "?raw");
      t.signal.throwIfAborted();
      return new Promise((resolve, reject) => {
        const request = ownedLoopbackHttpRequest(
          {
            hostname: "127.0.0.1",
            port: ownedPort,
            method: "GET",
            path: `/@fs/${file.replaceAll("\\", "/")}${suffix}`,
            signal: t.signal,
            createConnection: () => ownedLoopbackConnect({ host: "127.0.0.1", port: ownedPort }),
          },
          (incoming) => {
            const chunks = [];
            let bytes = 0;
            incoming.on("data", (chunk) => {
              bytes += chunk.length;
              if (bytes > 16_384)
                incoming.destroy(new Error("bounded synthetic HTTP response exceeded"));
              else chunks.push(chunk);
            });
            incoming.on("error", reject);
            incoming.on("end", () =>
              resolve({
                status: incoming.statusCode,
                body: Buffer.concat(chunks).toString("utf8"),
              }),
            );
          },
        );
        request.on("error", reject);
        request.end();
      });
    }
    try {
      fs.mkdirSync(home, { recursive: true });
      fs.mkdirSync(served, { recursive: true });
      fs.writeFileSync(path.join(served, "package.json"), '{"private":true,"type":"module"}\n');
      fs.writeFileSync(publicFile, "SYNTHETIC_V108_ALLOWED_MARKER");
      for (const [file, marker] of files) {
        fs.mkdirSync(path.dirname(file), { recursive: true });
        fs.writeFileSync(file, marker, { mode: 0o600 });
      }
      Object.assign(process.env, ownedEnvironment);
      const { createVitest } = await import(pathToFileURL(rootRequire.resolve("vitest/node")).href);
      const creating = createVitest(
        {
          root: served,
          config: false,
          watch: false,
          ui: false,
          api: { middlewareMode: true, host: "127.0.0.1", allowWrite: false, allowExec: false },
          reporters: [],
          include: [],
          passWithNoTests: true,
        },
        {
          configFile: false,
          envFile: false,
          cacheDir: path.join(fixture, "cache"),
          // Keep Vitest's shipped default fs.deny; a handwritten deny list would
          // hide the regression. The allow root contains every negative fixture.
          server: { fs: { strict: true, allow: [served] } },
        },
        { stdout: silent, stderr: silent },
      );
      const closeOnAbort = () => {
        void creating.then((owned) => owned.close()).catch(() => {});
      };
      t.signal.addEventListener("abort", closeOnAbort, { once: true });
      try {
        context = await creating;
      } finally {
        t.signal.removeEventListener("abort", closeOnAbort);
      }
      t.signal.throwIfAborted();
      assert.equal(context.config.api.middlewareMode, true);
      assert.equal(context.config.api.allowWrite, false);
      assert.equal(context.config.api.allowExec, false);
      assert.equal(context.vite.httpServer, null);
      assert.ok(
        context.config.api.token === markers.get("data/vitest/.vitest-secret-token"),
        "Vitest must use the owned synthetic API token",
      );
      server = http.createServer(context.vite.middlewares);
      const listening = once(server, "listening", { signal: t.signal });
      server.listen({ port: 0, host: "127.0.0.1", signal: t.signal });
      await listening;
      const address = server.address();
      assert.equal(address.address, "127.0.0.1");
      assert.ok(address.port > 0);
      ownedPort = address.port;
      const positive = await getOwnedFile(publicFile);
      assert.equal(positive.status, 200);
      assert.equal(positive.body, "SYNTHETIC_V108_ALLOWED_MARKER");
      for (const file of files.keys()) {
        for (const suffix of ["", "?raw"]) {
          const denied = await getOwnedFile(file, suffix);
          assert.ok(
            [403, 404].includes(denied.status),
            `synthetic deny-list status ${denied.status}`,
          );
          for (const marker of markers.values()) assert.equal(denied.body.includes(marker), false);
        }
      }
      assert.equal(networkCalls, 0);
    } finally {
      try {
        const cleanup = [];
        if (server) {
          server.closeAllConnections();
          cleanup.push(
            new Promise((resolve, reject) =>
              server.close((error) =>
                error && error.code !== "ERR_SERVER_NOT_RUNNING" ? reject(error) : resolve(),
              ),
            ),
          );
        }
        if (context) cleanup.push(context.close());
        const outcomes = await Promise.allSettled(cleanup);
        for (const outcome of outcomes) {
          if (outcome.status === "rejected") throw outcome.reason;
        }
      } finally {
        silent.destroy();
        for (const [key, previous] of Object.entries(previousEnvironment)) {
          if (previous === undefined) delete process.env[key];
          else process.env[key] = previous;
        }
        fs.rmSync(fixture, { recursive: true, force: true });
      }
    }
  },
);
