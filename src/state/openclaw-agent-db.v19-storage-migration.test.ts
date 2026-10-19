import fs from "node:fs";
import { constants, DatabaseSync } from "node:sqlite";
import { describe, expect, it } from "vitest";
import { decodeMemoryEmbedding } from "../../packages/memory-host-sdk/src/host/embedding-vector.js";
import { sha256Hex } from "../infra/crypto-digest.js";
import { resolveZstdCodec } from "../infra/zstd-codec.js";
import { withOpenClawTestState } from "../test-utils/openclaw-test-state.js";
import { OPENCLAW_AGENT_SCHEMA_VERSION } from "./openclaw-agent-db-contract.js";
import { withAgentDatabaseMaintenanceLease } from "./openclaw-agent-db-maintenance-lease.js";
import { ensureOpenClawAgentDatabaseSchema } from "./openclaw-agent-db-schema.js";

// Frozen public schema from 9.4 commit 0aad0267ab89ae16a9ba98d8ef8026bcc20534d6.
// All rows below are synthetic; ANY is a historical input, never the target schema.
const historicalSchema = fs.readFileSync(
  new URL("../../test/fixtures/sqlite/openclaw-agent-schema-v19-any.sql", import.meta.url),
  "utf8",
);
const transcript = ` {"type":"message","message":{"role":"user","content":${JSON.stringify("saffronquasar 雪 ".repeat(1024))}}}\n`;

function seed(db: DatabaseSync): void {
  db.exec(historicalSchema);
  db.exec(`
    PRAGMA user_version = 19;
    INSERT INTO schema_meta VALUES ('primary', 'agent', 19, 'main', '2026.9.4', 1, 1);
    INSERT INTO session_nodes(session_key, current_session_id, entry_json, updated_at)
      VALUES('agent:main:history', 'history', '{"sessionId":"history","updatedAt":2}', 2);
    INSERT INTO session_windows(session_id, session_key, created_at, updated_at)
      VALUES('history', 'agent:main:history', 1, 2);
    INSERT INTO memory_index_sources(path, source, hash, mtime, size)
      VALUES('memory/note.md', 'memory', 'original-hash', 1.5, 42);
  `);
  db.prepare(
    "INSERT INTO transcript_events(rowid, session_id, seq, event_json, created_at) VALUES(41, 'history', 7, ?, 11)",
  ).run(transcript);
  const embeddings = [
    "[1.0000000000000002,0.1]",
    Buffer.from("0000803f0000003f", "hex"),
    Buffer.alloc(0),
  ];
  for (const [index, embedding] of embeddings.entries()) {
    db.prepare(`INSERT INTO memory_index_chunks(rowid, id, path, source, start_line, end_line, hash, model, text, embedding, updated_at)
      VALUES(?, ?, 'memory/note.md', 'memory', 1, 3, 'chunk-hash', 'synthetic', 'saffronquasar memory', ?, 19)`).run(
      17 + index,
      `chunk-${index}`,
      embedding,
    );
    db.prepare(
      "INSERT INTO memory_index_chunk_provenance VALUES(?, 'owner', 'interactive', 18, 'older-chunk')",
    ).run(`chunk-${index}`);
    db.prepare(
      "INSERT INTO memory_index_chunk_recall_metadata VALUES(?, 7, '[\"saffronquasar\"]', 'project')",
    ).run(`chunk-${index}`);
    db.prepare(`INSERT INTO memory_embedding_cache(rowid, provider, model, provider_key, hash, embedding, dims, updated_at)
      VALUES(?, 'synthetic', 'model', 'provider-key', ?, ?, ?, 20)`).run(
      23 + index,
      `chunk-${index}`,
      embedding,
      index === 2 ? 0 : 2,
    );
  }
}

const preservedTables = [
  "session_windows",
  "memory_index_sources",
  "memory_index_chunk_provenance",
  "memory_index_chunk_recall_metadata",
  "memory_index_state",
] as const;

function preserved(db: DatabaseSync) {
  return Object.fromEntries(
    preservedTables.map((table) => [
      table,
      db.prepare(`SELECT * FROM ${table} ORDER BY rowid`).all(),
    ]),
  );
}

function snapshot(db: DatabaseSync) {
  return {
    schema: db.prepare("SELECT type, name, sql FROM sqlite_schema ORDER BY type, name").all(),
    version: db.prepare("PRAGMA user_version").get(),
    tables: Object.fromEntries(
      [
        "schema_meta",
        "session_nodes",
        "transcript_events",
        "memory_index_chunks",
        "memory_embedding_cache",
      ].map((table) => [table, db.prepare(`SELECT rowid, * FROM ${table} ORDER BY rowid`).all()]),
    ),
    preserved: preserved(db),
  };
}

describe("agent schema 19 storage migration", () => {
  it("publishes canonical storage while preserving mixed historical vectors and transcript bytes", async () => {
    expect(sha256Hex(historicalSchema)).toBe(
      "71498f9c490189123db153ea73d1c6fd69b7f4d657714b0a08e561973fd415be",
    );
    await withOpenClawTestState({ scenario: "minimal" }, async (state) => {
      const pathname = state.path("historical19.sqlite");
      const db = new DatabaseSync(pathname);
      try {
        seed(db);
        const before = preserved(db);
        await withAgentDatabaseMaintenanceLease({ env: state.env }, async () => {
          ensureOpenClawAgentDatabaseSchema(db, {
            agentId: "main",
            path: pathname,
            env: state.env,
          });
        });
        expect(db.prepare("PRAGMA user_version").get()).toEqual({
          user_version: OPENCLAW_AGENT_SCHEMA_VERSION,
        });
        expect(db.prepare("SELECT schema_version FROM schema_meta").get()).toEqual({
          schema_version: OPENCLAW_AGENT_SCHEMA_VERSION,
        });
        expect(preserved(db)).toEqual(before);
        const vectors = [[1 + Number.EPSILON, 0.1], [1, 0.5], []];
        for (const [table, firstRowid] of [
          ["memory_index_chunks", 17],
          ["memory_embedding_cache", 23],
        ] as const) {
          expect(
            db.prepare("SELECT type FROM pragma_table_info(?) WHERE name = 'embedding'").get(table),
          ).toEqual({ type: "BLOB" });
          const rows = db
            .prepare(`SELECT rowid AS rowid, embedding, updated_at FROM ${table} ORDER BY rowid`)
            .all();
          expect(rows).toHaveLength(3);
          for (const [index, row] of rows.entries()) {
            expect(row.rowid).toBe(firstRowid + index);
            expect(row.updated_at).toBe(table === "memory_index_chunks" ? 19 : 20);
            if (!(row.embedding instanceof Uint8Array)) {
              throw new Error("Expected canonical binary vector");
            }
            expect(decodeMemoryEmbedding(row.embedding)).toEqual(vectors[index]);
          }
        }
        const event = db
          .prepare(
            "SELECT rowid, seq, created_at, event_json, event_zstd, event_utf8_bytes FROM transcript_events",
          )
          .get()!;
        expect(event).toMatchObject({ rowid: 41, seq: 7, created_at: 11, event_json: null });
        if (!(event.event_zstd instanceof Uint8Array)) {
          throw new Error("Expected compressed transcript");
        }
        expect(
          resolveZstdCodec()!.decompress(event.event_zstd, Number(event.event_utf8_bytes)),
        ).toEqual(Buffer.from(transcript));
        expect(
          db
            .prepare(
              "SELECT count(*) AS count FROM memory_index_meta WHERE key = 'memory_vector_rebuild_v1'",
            )
            .get(),
        ).toEqual({ count: 0 });
        expect(db.prepare("PRAGMA foreign_key_check").all()).toEqual([]);
        expect(db.prepare("PRAGMA integrity_check").get()).toEqual({ integrity_check: "ok" });
        const migrated = snapshot(db);
        ensureOpenClawAgentDatabaseSchema(db, { agentId: "main", path: pathname, env: state.env });
        expect(snapshot(db)).toEqual(migrated);
      } finally {
        db.close();
      }
    });
  });

  it("rejects unknown memory shape before constructing the transcript rewrite", async () => {
    await withOpenClawTestState({ scenario: "minimal" }, async (state) => {
      const pathname = state.path("unsupported19.sqlite");
      const db = new DatabaseSync(pathname);
      try {
        seed(db);
        db.exec("ALTER TABLE memory_embedding_cache ADD COLUMN operator_note TEXT");
        const before = snapshot(db);
        const rewritten: string[] = [];
        db.setAuthorizer((action, name) => {
          if (
            action === constants.SQLITE_CREATE_TABLE &&
            name === "transcript_events_payload_migration"
          ) {
            rewritten.push(name);
          }
          return constants.SQLITE_OK;
        });
        await expect(
          withAgentDatabaseMaintenanceLease({ env: state.env }, async () => {
            ensureOpenClawAgentDatabaseSchema(db, {
              agentId: "main",
              path: pathname,
              env: state.env,
            });
          }),
        ).rejects.toThrow(/memory storage memory_embedding_cache: column definitions differ/);
        db.setAuthorizer(null);
        expect(rewritten).toEqual([]);
        expect(snapshot(db)).toEqual(before);
      } finally {
        db.setAuthorizer(null);
        db.close();
      }
    });
  });

  it("rolls schema, vectors and transcripts back when final publication is refused", async () => {
    await withOpenClawTestState({ scenario: "minimal" }, async (state) => {
      const pathname = state.path("rollback19.sqlite");
      const db = new DatabaseSync(pathname);
      try {
        seed(db);
        const before = snapshot(db);
        let reachedPublication = false;
        db.setAuthorizer((action, name, value) => {
          if (
            action === constants.SQLITE_PRAGMA &&
            name === "user_version" &&
            value === String(OPENCLAW_AGENT_SCHEMA_VERSION)
          ) {
            reachedPublication = true;
            return constants.SQLITE_DENY;
          }
          return constants.SQLITE_OK;
        });
        await expect(
          withAgentDatabaseMaintenanceLease({ env: state.env }, async () => {
            ensureOpenClawAgentDatabaseSchema(db, {
              agentId: "main",
              path: pathname,
              env: state.env,
            });
          }),
        ).rejects.toThrow(/authoriz/i);
        db.setAuthorizer(null);
        expect(reachedPublication).toBe(true);
        expect(snapshot(db)).toEqual(before);
        expect(db.prepare("PRAGMA foreign_key_check").all()).toEqual([]);
      } finally {
        db.setAuthorizer(null);
        db.close();
      }
    });
  });
});
