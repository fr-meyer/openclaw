import fs from "node:fs/promises";
import path from "node:path";
import { afterEach, expect, it, vi } from "vitest";
import { withOpenClawTestState } from "../../../../src/test-utils/openclaw-test-state.js";
import { openOpenClawAgentDatabase, closeOpenClawAgentDatabaseByPathAsync, runOpenClawAgentWriteTransaction } from "../../../../src/state/openclaw-agent-db.js";
import { replaceSessionEntry } from "../../../../src/config/sessions/session-accessor.sqlite-entry.js";
import { replaceTranscriptEvents } from "../../../../src/config/sessions/session-accessor.sqlite-transcript-write.js";
import { waitForSessionTranscriptIndexReconcile } from "../../../../src/config/sessions/session-transcript-reconcile.js";
import { runSessionColdStorageMaintenance } from "../../../../src/config/sessions/session-cold-storage.js";
import { registerSecretValueForRedaction } from "../../../../src/logging/secret-redaction-registry.js";
import * as snapshots from "../../../../src/infra/sqlite-snapshot-source.js";
import * as runtime from "./openclaw-runtime-session.js";
import { buildSessionEntry, buildSessionEntryInProcess, buildSessionEntryFromSnapshot, readSessionEntryResetRecallCutoff, type BuildSessionEntryOptions } from "./session-files.js";
afterEach(() => vi.restoreAllMocks());
async function fixture(run: (value: Awaited<ReturnType<typeof arrange>>) => Promise<void>, text = "synthetic native shared projection") {
  await withOpenClawTestState({ label: "sdk-owned-no-restore", scenario: "minimal" }, async (state) => run(await arrange(state.env, text)));
}
async function arrange(env: NodeJS.ProcessEnv, text: string) {
  const target = { agentId: "main", sessionId: "sdk-native", sessionKey: "agent:main:sdk-native", env };
  await replaceSessionEntry(target, { sessionId: target.sessionId, updatedAt: 1 });
  await replaceTranscriptEvents(target, [{ type: "session", id: target.sessionId, version: 3 }, { type: "reset", id: "reset" },
    { type: "message", id: "user", timestamp: 1000, message: { role: "user", content: text } },
    { type: "message", id: "answer", timestamp: 2000, message: { role: "assistant", content: "native answer" } }]);
  await waitForSessionTranscriptIndexReconcile({ agentId: "main", env });
  const database = openOpenClawAgentDatabase({ agentId: "main", env });
  const options: BuildSessionEntryOptions = { agentId: target.agentId, sessionId: target.sessionId, sessionKey: target.sessionKey, storePath: database.path, readPolicy: "no-restore" };
  return { target: { ...target, storePath: database.path }, database, options };
}
it("uses actual admitted native snapshot and identical shared projection/redaction/hash/provenance/reset metadata", async () => {
  const secret = "r17-native-synthetic-exact-secret-parity"; registerSecretValueForRedaction(secret);
  await fixture(async ({ database, options }) => {
    const { readPolicy, ...ordinaryOptions } = options;
    const ordinary = await buildSessionEntryInProcess(database.path, ordinaryOptions);
    const writes = database.db.prepare("SELECT total_changes() AS n").get(); const files = await fs.readdir(path.dirname(database.path));
    const opener = vi.spyOn(snapshots, "openSqliteReadOnlyDatabase"); const restore = vi.spyOn(runtime, "readRestoredSessionTranscript");
    const worker = vi.spyOn(runtime, "prepareSessionEntryInWorker"); const materialize = vi.spyOn(runtime, "materializeSessionArchiveForRead");
    const entry = await buildSessionEntry(database.path, options);
    expect(entry).toEqual(ordinary); expect(entry?.content).not.toContain(secret);
    if (!entry || !ordinary) { throw new Error("native projection missing"); }
    expect(readSessionEntryResetRecallCutoff(entry)).toEqual(readSessionEntryResetRecallCutoff(ordinary));
    expect(database.db.prepare("SELECT total_changes() AS n").get()).toEqual(writes); expect(await fs.readdir(path.dirname(database.path))).toEqual(files);
    expect(opener).not.toHaveBeenCalled(); expect(restore).not.toHaveBeenCalled(); expect(worker).not.toHaveBeenCalled(); expect(materialize).not.toHaveBeenCalled();
  }, secret);
});
it("refuses an ownerless process without falling back to worker/fresh open/restore", async () => {
  await fixture(async ({ database, options }) => {
    await closeOpenClawAgentDatabaseByPathAsync(database.path, "main");
    const opener = vi.spyOn(snapshots, "openSqliteReadOnlyDatabase"); const worker = vi.spyOn(runtime, "prepareSessionEntryInWorker"); const restore = vi.spyOn(runtime, "readRestoredSessionTranscript");
    await expect(buildSessionEntry(database.path, options)).rejects.toMatchObject({ status: "unverified" });
    expect(opener).not.toHaveBeenCalled(); expect(worker).not.toHaveBeenCalled(); expect(restore).not.toHaveBeenCalled();
  });
});
it("refuses actual cold native source without restoring/materializing", async () => {
  await fixture(async ({ target, database, options }) => {
    runOpenClawAgentWriteTransaction(({ db }) => { db.prepare("UPDATE session_windows SET updated_at = 1, transcript_updated_at = 1 WHERE session_id = ?").run(target.sessionId); }, { agentId: "main", env: target.env });
    await runSessionColdStorageMaintenance({ config: { agents: { entries: { main: {} } }, session: { store: database.path, maintenance: { coldStorage: { enabled: true, afterDays: 30 } } } } });
    const owner = openOpenClawAgentDatabase({ agentId: "main", env: target.env });
    expect(owner.db.prepare("SELECT session_id FROM session_transcript_cold_archives WHERE session_id = ?").get(target.sessionId)).toBeDefined();
    const restore = vi.spyOn(runtime, "readRestoredSessionTranscript"); const materialize = vi.spyOn(runtime, "materializeSessionArchiveForRead"); const opener = vi.spyOn(snapshots, "openSqliteReadOnlyDatabase");
    await expect(buildSessionEntry(database.path, options)).rejects.toMatchObject({ status: "unverified" });
    expect(restore).not.toHaveBeenCalled(); expect(materialize).not.toHaveBeenCalled(); expect(opener).not.toHaveBeenCalled();
  });
});
it("denies forged public snapshots, opaque callbacks, mismatches and caller eligibility/activity hints", async () => {
  await fixture(async ({ target, database, options }) => {
    const snapshot = runtime.readTranscriptExportSnapshotReadOnlySync(target); if (!snapshot) { throw new Error("fixture snapshot missing"); }
    const observer = vi.fn(); const source = { memoryEntry: vi.fn() };
    await expect(buildSessionEntryFromSnapshot(database.path, { ...target, readPolicy: "no-restore" }, { ...snapshot, events: [] }, observer)).rejects.toMatchObject({ status: "unverified" });
    await expect(buildSessionEntry(database.path, options, source)).rejects.toMatchObject({ status: "unverified" });
    for (const override of [{ onTranscriptMessage: observer }, { generatedByCronRun: false }, { generatedByDreamingNarrative: true }, { sessionKind: "unknown" as const }, { updatedAtMs: 7 }, { sessionId: "foreign" }, { sessionKey: "agent:main:unknown" }]) {
      await expect(buildSessionEntry(database.path, { ...options, ...override })).rejects.toMatchObject({ status: "unverified" });
    }
    expect(observer).not.toHaveBeenCalled(); expect(source.memoryEntry).not.toHaveBeenCalled();
  });
});
it("captures caller options and retries with real redaction revision while projecting actual native data", async () => {
  const secret = "r17-native-synthetic-late-registry-secret";
  await fixture(async ({ database, options }) => {
    const mutable = { ...options, parseYieldEveryLines: 1 }; const pending = buildSessionEntry(database.path, mutable);
    mutable.sessionId = "foreign"; mutable.sessionKey = "agent:main:foreign"; delete mutable.readPolicy;
    registerSecretValueForRedaction(secret);
    const entry = await pending; expect(entry?.content).not.toContain(secret); expect(entry?.content).toContain("Assistant: native answer");
  }, secret);
});

it("derives cron/dreaming eligibility only from the actual bound native session key", async () => {
  await fixture(async ({ target, database }) => {
    for (const [sessionId, sessionKey] of [["cron-native", "agent:main:cron:synthetic:run:one"], ["dream-native", "agent:main:dreaming-narrative-synthetic"]]) {
      const actual = { agentId: "main", sessionId, sessionKey, env: target.env };
      await replaceSessionEntry(actual, { sessionId, updatedAt: 1 });
      await replaceTranscriptEvents(actual, [{ type: "session", id: sessionId, version: 3 }, { type: "message", id: "u", timestamp: 1000, message: { role: "user", content: "excluded native eligibility text" } }]);
      await waitForSessionTranscriptIndexReconcile({ agentId: "main", env: target.env });
      const entry = await buildSessionEntry(database.path, { agentId: "main", sessionId, sessionKey, storePath: database.path, readPolicy: "no-restore" });
      expect(entry?.content).not.toContain("excluded native eligibility text");
    }
  });
});
