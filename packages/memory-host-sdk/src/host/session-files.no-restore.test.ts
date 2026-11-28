import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { encodeSessionArchiveContent } from "../../../../src/config/sessions/archive-compression.js";
import * as runtime from "./openclaw-runtime-session.js";
import {
  buildSessionEntry,
  buildSessionEntryInProcess,
  type BuildSessionEntryOptions,
} from "./session-files.js";
let root: string;
let stateDir: string;
const raw = [
  {
    type: "message",
    message: { role: "user", content: "Synthetic warm user text", timestamp: 1000 },
  },
  { type: "message", message: { role: "tool", content: "Tool-only content", timestamp: 2000 } },
  { type: "message", message: { role: "assistant", content: "Synthetic answer", timestamp: 3000 } },
]
  .map((line) => JSON.stringify(line))
  .join("\n");
beforeEach(async () => {
  root = await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), "session-no-restore-")));
  stateDir = path.join(root, "isolated-state");
  await fs.mkdir(path.join(stateDir, "agents", "main", "sessions"), { recursive: true });
  vi.stubEnv("OPENCLAW_STATE_DIR", stateDir);
  await fs.writeFile(path.join(root, "sessions.json"), "{}");
});
afterEach(async () => {
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
  await fs.rm(root, { recursive: true, force: true });
});
async function warm() {
  const filename = path.join(root, "warm.jsonl");
  await fs.writeFile(filename, raw);
  return filename;
}
describe("actual native session builder no-restoration policy", () => {
  it("reuses canonical warm content/provenance/redaction/eligibility and projection hash", async () => {
    const filename = await warm();
    const before = await fs.readFile(filename);
    const ordinary = await buildSessionEntry(filename);
    const noRestore = await buildSessionEntry(filename, { readPolicy: "no-restore" });
    expect(noRestore).toEqual(ordinary);
    expect(noRestore?.content).toContain("Synthetic warm user text");
    expect(noRestore?.content).not.toContain("Tool-only content");
    expect(noRestore?.lineProvenance).toEqual(ordinary?.lineProvenance);
    expect(await fs.readFile(filename)).toEqual(before);
  });
  it("preserves the real ordinary encoded-archive materialization route", async () => {
    const encoded = encodeSessionArchiveContent(raw);
    const filename = path.join(
      root,
      "native.jsonl.reset.2026-07-01T10-00-00.000Z" + encoded.suffix,
    );
    await fs.writeFile(filename, encoded.bytes);
    const materialize = vi.spyOn(runtime, "materializeSessionArchiveForRead");
    const entry = await buildSessionEntry(filename);
    expect(entry?.content).toContain("Synthetic warm user text");
    expect(materialize).toHaveBeenCalledWith(filename);
  });
  it("refuses actual archive inputs before native materialization or restoration", async () => {
    const encoded = encodeSessionArchiveContent(raw);
    const filename = path.join(
      root,
      "native.jsonl.reset.2026-07-01T10-00-00.000Z" + encoded.suffix,
    );
    await fs.writeFile(filename, encoded.bytes);
    const materialize = vi.spyOn(runtime, "materializeSessionArchiveForRead");
    const restore = vi.spyOn(runtime, "readRestoredSessionTranscript");
    await expect(buildSessionEntry(filename, { readPolicy: "no-restore" })).rejects.toMatchObject({
      status: "unverified",
      reason: "archive",
    });
    expect(materialize).not.toHaveBeenCalled();
    expect(restore).not.toHaveBeenCalled();
    expect(await fs.readFile(filename)).toEqual(encoded.bytes);
  });
  it("refuses unattested SQLite or cold custody before worker, incognito or restore callbacks", async () => {
    const worker = vi.spyOn(runtime, "prepareSessionEntryInWorker");
    const actor = vi.spyOn(runtime, "captureIncognitoMemoryReader");
    const restore = vi.spyOn(runtime, "readRestoredSessionTranscript");
    await expect(
      buildSessionEntry(path.join(root, "cold.jsonl"), {
        readPolicy: "no-restore",
        agentId: "main",
        sessionId: "cold",
        storePath: path.join(root, "sessions.json"),
      }),
    ).rejects.toMatchObject({ status: "unverified", reason: "unsupported-sqlite-custody" });
    await expect(
      buildSessionEntry(path.join(root, "cold.jsonl"), {
        readPolicy: "no-restore",
        agentId: "main",
      }),
    ).rejects.toMatchObject({ status: "unverified" });
    await expect(
      buildSessionEntry(path.join(root, "cold.jsonl"), {
        readPolicy: "no-restore",
        sessionKey: "opaque-session",
      }),
    ).rejects.toMatchObject({ reason: "opaque-reader" });
    expect(worker).not.toHaveBeenCalled();
    expect(actor).not.toHaveBeenCalled();
    expect(restore).not.toHaveBeenCalled();
  });
  it("does not invoke opaque source or transcript observer callbacks", async () => {
    const filename = await warm();
    const source = { memoryEntry: vi.fn() };
    const observer = vi.fn();
    await expect(
      buildSessionEntry(filename, { readPolicy: "no-restore" }, source),
    ).rejects.toMatchObject({ status: "unverified", reason: "opaque-reader" });
    await expect(
      buildSessionEntry(filename, { readPolicy: "no-restore", onTranscriptMessage: observer }),
    ).rejects.toMatchObject({ reason: "opaque-reader" });
    expect(source.memoryEntry).not.toHaveBeenCalled();
    expect(observer).not.toHaveBeenCalled();
  });
  it("rejects missing, malformed and unreadable metadata instead of best-effort null/empty", async () => {
    await expect(
      buildSessionEntry(path.join(root, "missing.jsonl"), { readPolicy: "no-restore" }),
    ).rejects.toMatchObject({ status: "unverified" });
    const filename = await warm();
    await fs.writeFile(filename, "not valid JSON");
    await expect(buildSessionEntry(filename, { readPolicy: "no-restore" })).rejects.toMatchObject({
      reason: "unprojectable",
    });
    await fs.writeFile(filename, raw);
    await fs.writeFile(path.join(root, "sessions.json"), "broken metadata");
    await expect(buildSessionEntry(filename, { readPolicy: "no-restore" })).rejects.toMatchObject({
      status: "unverified",
    });
  });
  it("captures no-restore policy before first yield so caller cannot enable best-effort fallback", async () => {
    const filename = await warm();
    await fs.writeFile(filename, "not valid JSON");
    const options: BuildSessionEntryOptions = { readPolicy: "no-restore", parseYieldEveryLines: 1 };
    const pending = buildSessionEntry(filename, options);
    options.readPolicy = undefined;
    await expect(pending).rejects.toMatchObject({ status: "unverified", reason: "unprojectable" });
  });
  it("refuses direct in-process custom projection callbacks in this explicit mode", async () => {
    const filename = await warm();
    const redactor = vi.fn((text: string) => text);
    await expect(
      buildSessionEntryInProcess(filename, { readPolicy: "no-restore" }, redactor),
    ).rejects.toMatchObject({ reason: "opaque-reader" });
    expect(redactor).not.toHaveBeenCalled();
  });
  it("refuses physical canonical candidates under a symlink-configured state root before callbacks", async () => {
    const alias = path.join(root, "state-alias");
    await fs.symlink(stateDir, alias, "dir");
    vi.stubEnv("OPENCLAW_STATE_DIR", alias);
    const canonical = path.join(stateDir, "agents", "main", "sessions", "warm.jsonl");
    await fs.writeFile(canonical, raw);
    await fs.writeFile(path.join(path.dirname(canonical), "sessions.json"), "{}");
    const worker = vi.spyOn(runtime, "prepareSessionEntryInWorker");
    const actor = vi.spyOn(runtime, "captureIncognitoMemoryReader");
    const restore = vi.spyOn(runtime, "readRestoredSessionTranscript");
    const materialize = vi.spyOn(runtime, "materializeSessionArchiveForRead");
    await expect(buildSessionEntry(canonical, { readPolicy: "no-restore" })).rejects.toMatchObject({
      status: "unverified",
      reason: "opaque-reader",
    });
    expect(worker).not.toHaveBeenCalled();
    expect(actor).not.toHaveBeenCalled();
    expect(restore).not.toHaveBeenCalled();
    expect(materialize).not.toHaveBeenCalled();
  });
  it("excludes canonical nested descendants and another owner's physically aliased root", async () => {
    const nested = path.join(stateDir, "agents", "main", "sessions", "nested", "deeper");
    await fs.mkdir(nested, { recursive: true });
    const canonical = path.join(nested, "warm.jsonl");
    await fs.writeFile(canonical, raw);
    await fs.writeFile(path.join(nested, "sessions.json"), "{}");
    await expect(buildSessionEntry(canonical, { readPolicy: "no-restore" })).rejects.toMatchObject({
      status: "unverified",
    });
    const external = path.join(root, "physical-owner");
    await fs.mkdir(external);
    await fs.writeFile(path.join(external, "warm.jsonl"), raw);
    await fs.writeFile(path.join(external, "sessions.json"), "{}");
    await fs.mkdir(path.join(stateDir, "agents", "other"));
    await fs.symlink(external, path.join(stateDir, "agents", "other", "sessions"), "dir");
    await expect(
      buildSessionEntry(path.join(external, "warm.jsonl"), { readPolicy: "no-restore" }),
    ).rejects.toMatchObject({ status: "unverified" });
  });
  it("refuses local candidate/parent aliases rather than falling back to physical local custody", async () => {
    const filename = await warm();
    const leaf = path.join(root, "alias.jsonl");
    await fs.symlink(filename, leaf);
    await expect(buildSessionEntry(leaf, { readPolicy: "no-restore" })).rejects.toMatchObject({
      status: "unverified",
    });
    const parent = path.join(root, "parent-alias");
    await fs.symlink(root, parent, "dir");
    await expect(
      buildSessionEntry(path.join(parent, "warm.jsonl"), { readPolicy: "no-restore" }),
    ).rejects.toMatchObject({ status: "unverified" });
  });
  it("fails closed when configured owner roots are missing or ambiguous", async () => {
    const filename = await warm();
    const canonical = path.join(stateDir, "agents", "main", "sessions");
    await fs.rm(canonical, { recursive: true });
    await expect(buildSessionEntry(filename, { readPolicy: "no-restore" })).rejects.toMatchObject({
      status: "unverified",
    });
    await fs.writeFile(canonical, "not a directory");
    await expect(buildSessionEntry(filename, { readPolicy: "no-restore" })).rejects.toMatchObject({
      status: "unverified",
    });
  });
  it("rejects both false, true and partial classification hints despite missing or corrupt sidecars", async () => {
    const filename = await warm();
    const sidecar = path.join(root, "sessions.json");
    const hints = [
      { generatedByDreamingNarrative: false, generatedByCronRun: false },
      { generatedByDreamingNarrative: true, generatedByCronRun: true },
      { generatedByCronRun: false },
      { generatedByDreamingNarrative: true },
    ];
    await fs.unlink(sidecar);
    for (const hint of hints) {
      await expect(
        buildSessionEntry(filename, { readPolicy: "no-restore", ...hint }),
      ).rejects.toMatchObject({ status: "unverified", reason: "opaque-reader" });
    }
    await fs.writeFile(sidecar, "broken sidecar");
    for (const hint of hints) {
      await expect(
        buildSessionEntry(filename, { readPolicy: "no-restore", ...hint }),
      ).rejects.toMatchObject({ status: "unverified", reason: "opaque-reader" });
    }
  });
  it("retains genuine no-hint native cron/dreaming exclusion and ordinary trusted-hint behavior", async () => {
    const filename = await warm();
    for (const sessionKey of [
      "agent:main:cron:synthetic:run:one",
      "agent:main:dreaming-narrative-synthetic",
    ]) {
      await fs.writeFile(
        path.join(root, "sessions.json"),
        JSON.stringify({ [sessionKey]: { sessionFile: filename } }),
      );
      const native = await buildSessionEntry(filename, { readPolicy: "no-restore" });
      expect(native?.content).not.toContain("Synthetic warm user text");
      await expect(
        buildSessionEntry(filename, {
          readPolicy: "no-restore",
          generatedByDreamingNarrative: false,
          generatedByCronRun: false,
        }),
      ).rejects.toMatchObject({ status: "unverified", reason: "opaque-reader" });
      const ordinary = await buildSessionEntry(filename, {
        generatedByDreamingNarrative: false,
        generatedByCronRun: false,
      });
      expect(ordinary?.content).toContain("Synthetic warm user text");
    }
  });
});
