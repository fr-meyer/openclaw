import { describe, expect, it } from "vitest";
import { fingerprintSourceRows, compareSourceObservations } from "./manager-source-observation.js";
describe("native source observation canonical identity", () => {
  const a = { source: "memory", identity: "a.md", content: "content", access: "mode" };
  const b = { source: "sessions", identity: "session", content: "other", access: "scope" };
  it("sorts and deduplicates stable native logical identities", () => {
    expect(fingerprintSourceRows("scope", [a, b, a])).toBe(fingerprintSourceRows("scope", [b, a]));
    expect(fingerprintSourceRows("scope", [{ access: "mode", content: "content", identity: "a.md", source: "memory" }])).toBe(fingerprintSourceRows("scope", [a]));
  });
  it("separates equal content by path, source and scope", () => {
    const original = fingerprintSourceRows("scope", [a]);
    expect(fingerprintSourceRows("scope", [{ ...a, identity: "b.md" }])).not.toBe(original);
    expect(fingerprintSourceRows("scope", [{ ...a, source: "sessions" }])).not.toBe(original);
    expect(fingerprintSourceRows("other-scope", [a])).not.toBe(original);
  });
  it("rejects contradictory duplicate native identities", () => {
    expect(() => fingerprintSourceRows("scope", [a, { ...a, content: "changed" }])).toThrow("conflict");
  });
  it("compares observations without claiming atomicity or trusting incomplete coverage", () => {
    const observed = { status: "observed-not-atomic" as const, scopeDigest: "scope", indexFence: "index", digest: "digest", entries: 1, issues: [] };
    expect(compareSourceObservations(observed, { ...observed })).toBe("same-observation-not-atomic");
    expect(compareSourceObservations(observed, { ...observed, digest: "changed" })).toBe("changed");
    expect(compareSourceObservations(observed, { ...observed, status: "unverified", digest: null })).toBe("unverified");
  });
});
