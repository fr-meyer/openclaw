import { createHash } from "node:crypto";
import path from "node:path";
import type { EmbeddingCandidateControllerIdentity } from "openclaw/plugin-sdk/embedding-provider-runtime-contract";
import type { MemoryCandidateRequest, MemoryCandidateStamp } from "./manager-candidate.js";
import type { MemoryIndexMeta } from "./manager-reindex-state.js";

const invalid = (): never => { throw new Error("Invalid persisted candidate schema v1"); };
const record = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v);
const text = (v: unknown): v is string => typeof v === "string" && v.length > 0;
const positive = (v: unknown): v is number => typeof v === "number" && Number.isSafeInteger(v) && v > 0;
const natural = (v: unknown): v is number => typeof v === "number" && Number.isSafeInteger(v) && v >= 0;
const operation = (v: unknown): v is string => typeof v === "string" && /^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$/.test(v);
const fence = (v: unknown): v is string => typeof v === "string" && /^[a-f0-9]{64}$/.test(v);
const filename = (v: unknown): v is string => text(v) && !v.includes("\0") && path.isAbsolute(v) && path.normalize(v) === v;
const keys = (v: Record<string, unknown>, allowed: string[]) => Object.keys(v).every((key) => allowed.includes(key));
const identity = (v: unknown): boolean => record(v) && keys(v, ["device", "inode"]) &&
  typeof v.device === "string" && /^(0|[1-9][0-9]*)$/.test(v.device) &&
  typeof v.inode === "string" && /^(0|[1-9][0-9]*)$/.test(v.inode);
function controller(v: unknown): v is EmbeddingCandidateControllerIdentity {
  if (!record(v) || !keys(v, ["agentId", "journal", "expected", "identity"]) || !text(v.agentId) ||
    !record(v.journal) || !record(v.expected)) { return false; }
  const j = v.journal, e = v.expected;
  return keys(j, ["path", "migrationId", "sourceRevision", "accountId", "route"]) &&
    filename(j.path) && operation(j.migrationId) && fence(j.sourceRevision) && text(j.accountId) && text(j.route) &&
    keys(e, ["model", "dimensions"]) && text(e.model) && positive(e.dimensions) &&
    v.identity === createHash("sha256").update(JSON.stringify({
      migrationId: j.migrationId, sourceRevision: j.sourceRevision, accountId: j.accountId,
      route: j.route, agentId: v.agentId, model: e.model, dimensions: e.dimensions,
    })).digest("hex");
}
function stamp(v: unknown): v is MemoryCandidateStamp {
  return record(v) && keys(v, ["version", "sourceFence", "controller", "cacheFileIdentity", "candidateFileIdentity",
    "operationId", "phase", "servingDatabasePath", "cacheDatabasePath", "servingFileIdentity"]) &&
    v.version === 1 && v.phase === "complete" && operation(v.operationId) && fence(v.sourceFence) &&
    filename(v.servingDatabasePath) && filename(v.cacheDatabasePath) && identity(v.servingFileIdentity) &&
    identity(v.cacheFileIdentity) && identity(v.candidateFileIdentity) &&
    (v.controller === undefined || controller(v.controller));
}
function metadata(v: unknown): v is MemoryIndexMeta {
  if (!record(v) || !stamp(v.candidate) || !text(v.provider) || !text(v.model) ||
    !text(v.providerKey) || !text(v.scopeHash) || !positive(v.vectorDims) ||
    !positive(v.chunkTokens) || !natural(v.chunkOverlap)) { return false; }
  for (const key of ["chunkingVersion", "embeddingInputFormatVersion", "provenanceVersion"]) {
    if (v[key] !== undefined && !natural(v[key])) { return false; }
  }
  if (v.ftsTokenizer !== undefined && !text(v.ftsTokenizer)) { return false; }
  if (v.sources !== undefined && (!Array.isArray(v.sources) ||
    !v.sources.every((source) => source === "memory" || source === "sessions"))) { return false; }
  const c = v.candidate.controller;
  return v.provider === "openai" ? c !== undefined && c.expected.model === v.model &&
    c.expected.dimensions === v.vectorDims && c.journal.migrationId === v.candidate.operationId &&
    c.journal.sourceRevision === v.candidate.sourceFence : c === undefined;
}
/** Candidate-only boundary. Ordinary metadata reader and legacy interpretation are unchanged.
 * Candidate v1, controller and file-identity objects are closed. Inherited metadata remains
 * extensible; known optional fields retain omission semantics. No providerKey/scope hash format guess.
 * This validates structure/linkage, not filesystem freshness or journal attestation.
 */
export function parseCandidateMetadata(serialized: unknown): MemoryIndexMeta {
  if (typeof serialized !== "string") { return invalid(); }
  let value: unknown;
  try { value = JSON.parse(serialized); } catch { return invalid(); }
  if (!metadata(value)) { return invalid(); }
  // JSON parsing makes an independent primitive/object snapshot, no caller-owned aliases.
  const freeze = (entry: unknown): void => {
    if (record(entry) || Array.isArray(entry)) { Object.values(entry).forEach(freeze); Object.freeze(entry); }
  };
  freeze(value);
  return value;
}
export function snapshotCandidateReloadRequest(value: unknown): MemoryCandidateRequest {
  if (!record(value) || !operation(value.operationId) || !record(value.expected) ||
    !text(value.expected.provider) || !text(value.expected.model) || !positive(value.expected.dimensions)) { return invalid(); }
  const expected = { provider: value.expected.provider, model: value.expected.model, dimensions: value.expected.dimensions };
  let admission: MemoryCandidateRequest["controller"];
  if (value.controller !== undefined) {
    const c = value.controller;
    if (!record(c) || !text(c.accountId) || !text(c.route) || !fence(c.sourceRevision)) { return invalid(); }
    admission = { accountId: c.accountId, route: c.route, sourceRevision: c.sourceRevision };
  }
  if ((expected.provider === "openai") !== (admission !== undefined)) { return invalid(); }
  return { operationId: value.operationId, expected, controller: admission };
}
