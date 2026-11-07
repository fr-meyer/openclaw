import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { afterAll, describe, expect, it } from "vitest";
import { useAutoCleanupTempDirTracker } from "../../test/helpers/temp-dir.js";
import type { EngineConnection } from "../infra/sql-connection.js";
import { OPENCLAW_STATE_SCHEMA_VERSION } from "./openclaw-state-db-contract.js";
import {
  closeOpenClawStateDatabaseAsync,
  openOpenClawStateDatabase,
  repairOpenClawStateDatabaseSchema,
} from "./openclaw-state-db.js";
import { resolveOpenClawStateSqlitePath } from "./openclaw-state-db.paths.js";

// Exact public SQL from the frozen fork predecessor, not a current schema with
// its version marker lowered. Lazy fragments and a whole-generation backup are
// covered by their owning backup/qualification suites rather than fabricated here.
const predecessorSchema = fs.readFileSync(
  new URL("../../test/fixtures/sqlite/openclaw-state-h3-schema-v20.sql", import.meta.url),
  "utf8",
);
const flowState =
  '{"activeWorker":{"sessionKey":"agent:reviewer:subagent:retained","runId":"run-1","taskId":"task-1","nativeGeneration":7}}';
const retentionJson =
  '{"completionRetention":{"idPrefix":"kept:","maxAgeMs":86400000,"maxEntries":2}}';
const sourceJson = '{"accountId":"account","channelId":"channel"}';
const metadataJson = '{"agentId":"main"}';
const resumeIdentity = '{"agentSessionId":" resume ","acpxSessionId":" acpx-resume "}';

function seedPredecessor(pathname: string): void {
  using database = new DatabaseSync(pathname);
  database.exec(predecessorSchema);
  database.exec(`PRAGMA user_version = 20;
    INSERT INTO schema_meta
      (meta_key, role, schema_version, created_at, updated_at)
      VALUES ('primary', 'global', 20, 1, 1);`);
  database
    .prepare(`INSERT INTO flow_runs
    (flow_id, sync_mode, owner_key, controller_id, revision, status, notify_policy,
     goal, state_json, created_at, updated_at)
    VALUES ('flow-1', 'managed', 'agent:main:publisher', 'publisher/v1', 4,
      'running', 'done_only', 'Retain the exact native claim', ?, 1, 1)`)
    .run(flowState);
  database
    .prepare(`INSERT INTO meeting_transcript_sessions
    (session_id, started_at, selector, export_key, session_slug, provider_id,
     source_json, metadata_json, created_at_ms, updated_at_ms)
    VALUES ('capture', '2026-10-01', 'capture-selector', 'capture-export',
      'capture-slug', 'synthetic', ?, ?, 1, 1)`)
    .run(sourceJson, metadataJson);
  database.exec(`INSERT INTO meeting_transcript_summaries
    (session_id, session_started_at, summary_json, utterance_count)
    VALUES ('capture', '2026-10-01', '{"overview":"retained overview"}', 0)`);
  database
    .prepare(`INSERT INTO delivery_queue_entries
    (queue_name, id, status, recovery_state, entry_json, enqueued_at, updated_at)
    VALUES ('synthetic', 'kept:row', 'completed', 'completed_bounded', ?, 1, 1)`)
    .run(retentionJson);
  for (const rowid of [7, 30]) {
    database
      .prepare(`INSERT INTO cron_run_receipts
      (rowid, receipt_id, store_key, job_id, config_revision, agent_id,
       request_run_id, status, owner_pid, started_at_ms, finished_at_ms)
      VALUES (?, ?, 'default', ?, 'revision', 'main', 'run-1', 'ok', 1, 100, 110)`)
      .run(rowid, `receipt-${rowid}`, `job-${rowid}`);
  }
  database
    .prepare(`INSERT INTO acp_sessions
    (session_key, session_id, backend, agent, runtime_session_name,
     identity_json, mode, state, last_activity_at, updated_at)
    VALUES ('agent:main:acp:retained', 'session-1', 'synthetic', 'main',
      'runtime-1', ?, 'persistent', 'idle', 1, 1)`)
    .run(resumeIdentity);
}

function retainedRows(database: EngineConnection) {
  return {
    flow: database
      .prepare(
        "SELECT flow_id, owner_key, controller_id, revision, status, state_json FROM flow_runs",
      )
      .all(),
    transcript: database
      .prepare("SELECT source_json, metadata_json FROM meeting_transcript_sessions")
      .all(),
    retention: database.prepare("SELECT entry_json FROM delivery_queue_entries").all(),
    resume: database.prepare("SELECT identity_json FROM acp_sessions").all(),
  };
}

describe("frozen H3 state-20 upgrade", () => {
  const directories = useAutoCleanupTempDirTracker((cleanup) => {
    afterAll(async () => {
      await closeOpenClawStateDatabaseAsync();
      cleanup();
    });
  });

  it.each(["runtime", "doctor"] as const)(
    "preserves populated predecessor rows and a separately restorable snapshot through %s",
    async (owner) => {
      const root = directories.make(`h3-state20-${owner}-`);
      const stateDir = path.join(root, "candidate");
      const pathname = resolveOpenClawStateSqlitePath({ OPENCLAW_STATE_DIR: stateDir });
      fs.mkdirSync(path.dirname(pathname), { recursive: true });
      seedPredecessor(pathname);
      const snapshot = path.join(root, "predecessor.sqlite");
      fs.copyFileSync(pathname, snapshot);
      const snapshotBytes = fs.readFileSync(snapshot);
      const snapshotHash = createHash("sha256").update(snapshotBytes).digest("hex");
      let original: ReturnType<typeof retainedRows>;
      {
        using source = new DatabaseSync(snapshot, { readOnly: true });
        original = retainedRows(source);
        expect(source.prepare("PRAGMA user_version").get()?.user_version).toBe(20);
        expect(
          source
            .prepare("PRAGMA table_info(cron_run_receipts)")
            .all()
            .some((column) => column.name === "cursor_id"),
        ).toBe(false);
      }
      const options = { path: pathname, env: { OPENCLAW_STATE_DIR: stateDir } };
      try {
        if (owner === "doctor") {
          expect(repairOpenClawStateDatabaseSchema(options).warnings).toEqual([]);
        }
        const { db } = openOpenClawStateDatabase(options);
        expect(OPENCLAW_STATE_SCHEMA_VERSION).toBe(22);
        expect(db.prepare("PRAGMA user_version").get()?.user_version).toBe(22);
        expect(db.prepare("SELECT schema_version FROM schema_meta").get()?.schema_version).toBe(22);
        expect(retainedRows(db)).toEqual(original);
        expect(
          db
            .prepare(
              "SELECT source_account_id, source_channel_id, metadata_agent_id FROM meeting_transcript_sessions",
            )
            .get(),
        ).toEqual({
          source_account_id: "account",
          source_channel_id: "channel",
          metadata_agent_id: "main",
        });
        expect(
          db
            .prepare(
              "SELECT retention_id_prefix, retention_max_age_ms, retention_max_entries FROM delivery_queue_entries",
            )
            .get(),
        ).toEqual({
          retention_id_prefix: "kept:",
          retention_max_age_ms: 86400000,
          retention_max_entries: 2,
        });
        expect(
          db
            .prepare("SELECT cursor_id, receipt_id FROM cron_run_receipts ORDER BY cursor_id")
            .all(),
        ).toEqual([
          { cursor_id: 7, receipt_id: "receipt-7" },
          { cursor_id: 30, receipt_id: "receipt-30" },
        ]);
        expect(
          db
            .prepare("SELECT resume_agent_session_id, resume_acpx_session_id FROM acp_sessions")
            .get(),
        ).toEqual({
          resume_agent_session_id: "resume",
          resume_acpx_session_id: "acpx-resume",
        });
      } finally {
        await closeOpenClawStateDatabaseAsync();
      }
      expect(createHash("sha256").update(fs.readFileSync(snapshot)).digest("hex")).toBe(
        snapshotHash,
      );
      const restored = path.join(root, "empty-restore", "openclaw.sqlite");
      fs.mkdirSync(path.dirname(restored));
      fs.copyFileSync(snapshot, restored, fs.constants.COPYFILE_EXCL);
      using predecessor = new DatabaseSync(restored, { readOnly: true });
      expect(predecessor.prepare("PRAGMA user_version").get()?.user_version).toBe(20);
      expect(
        predecessor.prepare("SELECT schema_version FROM schema_meta").get()?.schema_version,
      ).toBe(20);
      expect(retainedRows(predecessor)).toEqual(original);
    },
  );
});
