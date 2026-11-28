import assert from "node:assert/strict";
import { createRequire } from "node:module";
import path from "node:path";
import test from "node:test";

// Full-source CI resolves the actual development-only Sigstore chain. A tiny
// public package fixture may explicitly select its package directory; the native
// CI owner strips this override. No network or runtime configuration is read.
let cacheRequire;
if (process.env.HTTP_CACHE_TEST_PROJECT) {
  cacheRequire = createRequire(path.resolve(process.env.HTTP_CACHE_TEST_PROJECT, "package.json"));
} else {
  const rootRequire = createRequire(path.resolve(process.cwd(), "package.json"));
  const sigstoreRequire = createRequire(rootRequire.resolve("sigstore"));
  const signRequire = createRequire(sigstoreRequire.resolve("@sigstore/sign"));
  const fetchRequire = createRequire(signRequire.resolve("make-fetch-happen"));
  cacheRequire = createRequire(fetchRequire.resolve("http-cache-semantics"));
}
const CachePolicy = cacheRequire("./index.js");
const version = cacheRequire("./package.json").version;
const request = (headers = {}) => ({
  url: "https://registry.example.invalid/public-package",
  method: "GET",
  headers: { host: "registry.example.invalid", ...headers },
});
const clock = Date.UTC(2026, 9, 24);
class FixedClockPolicy extends CachePolicy {
  now() {
    return clock;
  }
}
function policy(headers = {}, req = request()) {
  return new FixedClockPolicy(req, {
    status: 200,
    headers: {
      date: new Date(clock).toUTCString(),
      "cache-control": "public, max-age=60",
      ...headers,
    },
  });
}

test("the selected development cache package is exactly 4.3.0", () => {
  assert.equal(version, "4.3.0");
});

test("public fresh response and serialized policy preserve the parent API", () => {
  const cached = policy({ etag: '"synthetic-version"' });
  assert.equal(cached.storable(), true);
  assert.equal(cached.satisfiesWithoutRevalidation(request()), true);
  assert.equal(cached.evaluateRequest(request()).response.status, 200);
  const reopened = CachePolicy.fromObject(cached.toObject());
  reopened.now = () => clock;
  assert.equal(reopened.satisfiesWithoutRevalidation(request()), true);
  const conditional = reopened.revalidationHeaders(request({ "cache-control": "no-cache" }));
  assert.equal(conditional["if-none-match"], '"synthetic-version"');
});

test("shared private and no-store responses are ineligible for storage", () => {
  for (const directive of ["private, max-age=60", "no-store"]) {
    assert.equal(policy({ "cache-control": directive }).storable(), false);
  }
});

test("inherited request headers cannot satisfy an own Vary header", () => {
  const cached = policy({ vary: "x-user" }, request({ "x-user": "synthetic-alice" }));
  const inherited = Object.assign(Object.create({ "x-user": "synthetic-alice" }), {
    host: "registry.example.invalid",
  });
  assert.equal(cached.satisfiesWithoutRevalidation({ ...request(), headers: inherited }), false);
  assert.equal(cached.satisfiesWithoutRevalidation(request({ "x-user": "synthetic-alice" })), true);
});

test("a wildcard in a Vary list always requires revalidation", () => {
  assert.equal(policy({ vary: "*, x-user" }).satisfiesWithoutRevalidation(request()), false);
});
