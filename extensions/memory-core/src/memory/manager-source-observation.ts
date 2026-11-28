import { constants } from "node:fs";
import fs from "node:fs/promises";
import path from "node:path";
import { createHash } from "node:crypto";
import { buildFileEntry, hashText, listMemoryFiles, normalizeExtraMemoryPathEntries,
  type MemorySource, type MemoryWorkspaceFiles } from "openclaw/plugin-sdk/memory-core-host-engine-storage";
import { type SessionTranscriptCorpusEntry } from "openclaw/plugin-sdk/memory-core-host-engine-sessions";

export type SourceObservation = {
  status: "observed-not-atomic" | "unverified";
  scopeDigest: string; indexFence: string; digest: string | null; entries: number;
  issues: readonly string[];
};
type Row = { source: string; identity: string; content: string; access: string };
const digest = (value: unknown) => createHash("sha256").update(JSON.stringify(value)).digest("hex");
/** Provider-independent canonical logical identities, not caller authority or an atomic barrier. */
export function fingerprintSourceRows(scope: string, rows: readonly Row[]): string {
  const unique = new Map<string, Row>();
  for (const row of rows) {
    const key = JSON.stringify([row.source, row.identity]); const prior = unique.get(key);
    if (prior && JSON.stringify([prior.content, prior.access]) !== JSON.stringify([row.content, row.access])) { throw new Error("Source identity conflict"); }
    unique.set(key, { source: row.source, identity: row.identity, content: row.content, access: row.access });
  }
  return digest([scope, [...unique].sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).map(([, row]) => row)]);
}
export function compareSourceObservations(a: SourceObservation, b: SourceObservation): "changed" | "same-observation-not-atomic" | "unverified" {
  if (a.status !== "observed-not-atomic" || b.status !== "observed-not-atomic" || !a.digest || !b.digest) { return "unverified"; }
  return a.digest === b.digest && a.scopeDigest === b.scopeDigest && a.indexFence === b.indexFence
    ? "same-observation-not-atomic" : "changed";
}
/** Private local source file custody only, NOT SQLite opened-handle custody. */
async function readBoundFile(filename: string) {
  const before = await fs.lstat(filename, { bigint: true });
  if (!before.isFile() || before.isSymbolicLink() || await fs.realpath(filename) !== filename) { throw new Error("Source custody unavailable"); }
  const handle = await fs.open(filename, constants.O_RDONLY | constants.O_NOFOLLOW);
  const state = (s: typeof before) => [s.dev, s.ino, s.size, s.mtimeNs, s.ctimeNs, s.mode, s.uid, s.gid].map(String).join(":");
  try {
    const opened = await handle.stat({ bigint: true });
    if (state(before) !== state(opened)) { throw new Error("Source substituted"); }
    const bytes = await handle.readFile();
    const after = await handle.stat({ bigint: true }); const leaf = await fs.lstat(filename, { bigint: true });
    if (state(opened) !== state(after) || state(after) !== state(leaf) || await fs.realpath(filename) !== filename) { throw new Error("Source changed during read"); }
    const parents: string[] = [];
    for (let parent = path.dirname(filename); ; parent = path.dirname(parent)) {
      const info = await fs.lstat(parent, { bigint: true });
      if (!info.isDirectory() || info.isSymbolicLink() || await fs.realpath(parent) !== parent) { throw new Error("Source parent custody unavailable"); }
      parents.push(digest([parent, String(info.dev), String(info.ino), String(info.mode), String(info.uid), String(info.gid)]));
      if (parent === path.dirname(parent)) { break; }
    }
    return { bytes, access: state(after) + ":" + digest(parents) };
  } finally { await handle.close(); }
}
export async function observeNativeSources(params: {
  workspaceDir: string; sources: readonly MemorySource[];
  settings: { extraPaths: Parameters<typeof listMemoryFiles>[1]; multimodal: Parameters<typeof listMemoryFiles>[2] };
  files?: MemoryWorkspaceFiles; indexFence: string;
  sessions: () => Promise<SessionTranscriptCorpusEntry[]>;
}): Promise<SourceObservation> {
  const sources = [...params.sources].sort();
  const settings = structuredClone(params.settings);
  const workspaceDir = params.workspaceDir;
  const files = params.files, sessions = params.sessions, indexFence = params.indexFence;
  const scopeDigest = digest({ workspaceDir, sources, settings });
  const rows: Row[] = []; const issues: string[] = [];
  try {
    if (!sources.length || sources.some((s) => s !== "memory" && s !== "sessions")) { throw new Error("Unsupported coverage"); }
    if (sources.includes("memory")) {
      if (files) { throw new Error("Remote source custody unavailable"); }
      const roots = [workspaceDir, path.join(workspaceDir, "memory"),
        ...normalizeExtraMemoryPathEntries(workspaceDir, settings.extraPaths).map((entry) => entry.path)];
      const rootsState = async () => {
        const result: string[] = [];
        for (const root of [...new Set(roots)].sort()) {
          try { const s = await fs.lstat(root, { bigint: true });
            if (s.isSymbolicLink() || await fs.realpath(root) !== root) { throw new Error("Root custody unavailable"); }
            result.push(digest([root, String(s.dev), String(s.ino), String(s.mode), String(s.uid), String(s.gid)]));
          } catch (error) { if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") { result.push(digest([root, "absent"])); } else { throw error; } }
        }
        return result;
      };
      const rootBefore = await rootsState(); let skipped = false;
      const list = async () => (await listMemoryFiles(workspaceDir, settings.extraPaths, settings.multimodal, () => { skipped = true; })).sort();
      const before = await list();
      for (const filename of before) {
        const bound = await readBoundFile(filename);
        const entry = await buildFileEntry(filename, workspaceDir, settings.multimodal);
        if (!entry || (entry.kind === "multimodal" ? entry.dataHash !== createHash("sha256").update(bound.bytes).digest("hex") : entry.hash !== hashText(bound.bytes.toString("utf8")))) { throw new Error("Native source read mismatch"); }
        const recheck = await readBoundFile(filename);
        if (bound.access !== recheck.access || !bound.bytes.equals(recheck.bytes)) { throw new Error("Source changed during native read"); }
        rows.push({ source: "memory", identity: entry.path, content: entry.hash, access: bound.access });
      }
      if (skipped || JSON.stringify(before) !== JSON.stringify(await list()) || JSON.stringify(rootBefore) !== JSON.stringify(await rootsState())) { throw new Error("Source inventory changed"); }
      rows.push({ source: "scope", identity: "memory-roots", content: digest(rootBefore), access: "native-local" });
    }
    if (sources.includes("sessions")) {
      // Native readonly corpus + actual native projected content. Array API has no
      // explicit complete/ACL continuation receipt: never upgrade this to complete.
      const before = await sessions();
      // buildSessionEntry can restore cold transcripts and has no readOnly option.
      // Do not call that mutating fallback from a read-only observation boundary.
      if (digest(before) !== digest(await sessions())) { throw new Error("Session inventory changed"); }
      issues.push("session-readonly-content-and-completeness-receipt-unavailable");
    }
  } catch { issues.push("native-source-coverage-or-read-unverified"); }
  // No path, raw content or underlying exception escapes this observation.
  return { status: issues.length ? "unverified" : "observed-not-atomic", scopeDigest,
    indexFence, digest: issues.length ? null : fingerprintSourceRows(scopeDigest, rows), entries: rows.length, issues };
}
