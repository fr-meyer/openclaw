import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  parseCandidateMetadata,
  snapshotCandidateReloadRequest,
} from "./manager-candidate-schema.js";
function valid() {
  const journal = {
    path: "/private/batch.sqlite",
    migrationId: "operation",
    sourceRevision: "a".repeat(64),
    accountId: "account",
    route: "synthetic",
  };
  const expected = { model: "model", dimensions: 256 };
  const controller = {
    agentId: "main",
    journal,
    expected,
    identity: createHash("sha256")
      .update(
        JSON.stringify({
          migrationId: journal.migrationId,
          sourceRevision: journal.sourceRevision,
          accountId: journal.accountId,
          route: journal.route,
          agentId: "main",
          model: expected.model,
          dimensions: expected.dimensions,
        }),
      )
      .digest("hex"),
  };
  return {
    provider: "openai",
    model: "model",
    providerKey: "key",
    scopeHash: "scope",
    vectorDims: 256,
    chunkTokens: 400,
    chunkOverlap: 80,
    sources: ["memory", "sessions"],
    chunkingVersion: 1,
    embeddingInputFormatVersion: 0,
    provenanceVersion: 1,
    ftsTokenizer: "unicode61",
    candidate: {
      version: 1,
      phase: "complete",
      operationId: "operation",
      sourceFence: journal.sourceRevision,
      servingDatabasePath: "/private/serving.sqlite",
      cacheDatabasePath: "/private/cache.sqlite",
      servingFileIdentity: { device: "1", inode: "2" },
      cacheFileIdentity: { device: "1", inode: "3" },
      candidateFileIdentity: { device: "1", inode: "4" },
      controller,
    },
  };
}
const reject = (value: unknown) =>
  expect(() => parseCandidateMetadata(JSON.stringify(value))).toThrow(
    "Invalid persisted candidate schema v1",
  );
describe("candidate-only serialized schema v1", () => {
  it("roundtrips known writer metadata independently and freezes nested identity", () => {
    const input = valid();
    const parsed = parseCandidateMetadata(JSON.stringify(input));
    expect(parsed).toEqual(input);
    expect(Object.isFrozen(parsed.candidate?.controller?.journal)).toBe(true);
    input.candidate.controller.journal.accountId = "changed";
    expect(parsed.candidate?.controller?.journal.accountId).toBe("account");
  });
  it("admits nonopenai and omitted optional ordinary fields without controller", () => {
    const { controller, ...candidate } = valid().candidate;
    expect(
      parseCandidateMetadata(
        JSON.stringify({
          provider: "mistral",
          model: "mistral-embed",
          providerKey: "key",
          scopeHash: "scope",
          vectorDims: 1024,
          chunkTokens: 400,
          chunkOverlap: 0,
          candidate,
        }),
      ).provider,
    ).toBe("mistral");
  });
  it("refuses malformed JSON, null, arrays and missing objects", () => {
    for (const raw of ["{", "null", "[]", "{}", "false", "0"]) {
      expect(() => parseCandidateMetadata(raw)).toThrow("schema v1");
    }
    for (const candidate of [
      null,
      [],
      { ...valid().candidate, controller: [] },
      { ...valid().candidate, controller: null },
    ]) {
      reject({ ...valid(), candidate });
    }
  });
  it("refuses every invalid closed stamp version, phase, path and identity", () => {
    for (const patch of [
      { version: 2 },
      { phase: "building" },
      { phase: "unknown" },
      { operationId: "../bad" },
      { sourceFence: "fake" },
      { servingDatabasePath: 4 },
      { cacheDatabasePath: "relative" },
      { surprise: true },
      { servingFileIdentity: { device: 1, inode: "2" } },
      { cacheFileIdentity: { device: "1", inode: [] } },
      { candidateFileIdentity: { device: "1", inode: "4", verified: true } },
    ]) {
      reject({ ...valid(), candidate: { ...valid().candidate, ...patch } });
    }
  });
  it("refuses nested controller corruption and fake digest despite matching length", () => {
    for (const patch of [
      { journal: null },
      { expected: [] },
      { identity: "f".repeat(64) },
      { agentId: 3 },
      { journal: { ...valid().candidate.controller.journal, accountId: false } },
      { expected: { model: "model", dimensions: 0 } },
      { unexpected: true },
    ]) {
      const v = valid();
      reject({
        ...v,
        candidate: { ...v.candidate, controller: { ...v.candidate.controller, ...patch } },
      });
    }
  });
  it("refuses wrong metadata primitives, unsafe integers and source collections", () => {
    for (const patch of [
      { providerKey: true },
      { scopeHash: {} },
      { vectorDims: Number.MAX_SAFE_INTEGER + 1 },
      { chunkTokens: 0 },
      { chunkOverlap: -1 },
      { chunkingVersion: "1" },
      { provenanceVersion: null },
      { embeddingInputFormatVersion: -1 },
      { ftsTokenizer: [] },
      { sources: {} },
      { sources: ["private"] },
      { sources: [null] },
    ]) {
      reject({ ...valid(), ...patch });
    }
  });
  it("validates unknown reload requests before nested use and captures primitives", () => {
    for (const request of [
      null,
      [],
      {},
      { operationId: "operation", expected: null },
      {
        operationId: "operation",
        expected: { provider: "openai", model: "model", dimensions: 256 },
        controller: [],
      },
      {
        operationId: "operation",
        expected: { provider: "mistral", model: "model", dimensions: Infinity },
      },
    ]) {
      expect(() => snapshotCandidateReloadRequest(request)).toThrow("schema v1");
    }
    const request = {
      operationId: "operation",
      expected: { provider: "openai", model: "model", dimensions: 256 },
      controller: { accountId: "account", route: "synthetic", sourceRevision: "a".repeat(64) },
    };
    const copy = snapshotCandidateReloadRequest(request);
    request.expected.model = "changed";
    expect(copy.expected.model).toBe("model");
  });
});
