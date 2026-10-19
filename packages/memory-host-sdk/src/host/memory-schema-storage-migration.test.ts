import { DatabaseSync } from "node:sqlite";
import { describe, expect, it, onTestFinished, vi } from "vitest";
import { decodeMemoryEmbedding, encodeMemoryEmbedding } from "./embedding-vector.js";
import {
  buildMemoryEmbeddingCacheSchema,
  MEMORY_INDEX_CHUNKS_SCHEMA_SQL,
} from "./memory-schema-base.js";
import {
  assertMemoryIndexStorageMigrationCompatible,
  migrateMemoryIndexStorage,
} from "./memory-schema-storage-migration.js";

function legacyDatabase(embeddingType: "TEXT" | "ANY" = "TEXT"): DatabaseSync {
  const db = new DatabaseSync(":memory:");
  onTestFinished(() => db.close());
  db.exec(`
    PRAGMA foreign_keys = ON;
    CREATE TABLE memory_index_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL) STRICT;
    CREATE TABLE memory_index_sources (
      id INTEGER PRIMARY KEY, path TEXT NOT NULL, source TEXT NOT NULL,
      hash TEXT NOT NULL, mtime REAL NOT NULL, size INTEGER NOT NULL, UNIQUE(path, source)
    ) STRICT;
    CREATE TABLE memory_index_chunks (
      id TEXT PRIMARY KEY, path TEXT NOT NULL, source TEXT NOT NULL DEFAULT 'memory',
      start_line INTEGER NOT NULL, end_line INTEGER NOT NULL, hash TEXT NOT NULL,
      model TEXT NOT NULL, text TEXT NOT NULL, embedding ${embeddingType} NOT NULL, updated_at INTEGER NOT NULL
    ) STRICT;
    CREATE TABLE memory_index_chunk_provenance (
      chunk_id TEXT PRIMARY KEY REFERENCES memory_index_chunks(id) ON DELETE CASCADE,
      origin_class TEXT NOT NULL, session_kind TEXT NOT NULL, observed_at INTEGER NOT NULL,
      supersedes_key TEXT
    ) STRICT;
    CREATE TABLE memory_embedding_cache (
      provider TEXT NOT NULL, model TEXT NOT NULL, provider_key TEXT NOT NULL,
      hash TEXT NOT NULL, embedding ${embeddingType} NOT NULL, dims INTEGER, updated_at INTEGER NOT NULL,
      PRIMARY KEY (provider, model, provider_key, hash)
    ) STRICT;
    CREATE VIRTUAL TABLE memory_index_chunks_fts USING fts5(
      text, id UNINDEXED, path UNINDEXED, source UNINDEXED, model UNINDEXED,
      start_line UNINDEXED, end_line UNINDEXED
    );
    INSERT INTO memory_index_sources VALUES(1, 'memory/a.md', 'memory', 'h', 123.5, 32);
    INSERT INTO memory_index_chunks(rowid, id, path, source, start_line, end_line, hash, model, text, embedding, updated_at)
      VALUES(7, 'logical-id', 'memory/a.md', 'memory', 1, 2, 'h', 'model', 'saffronquasar', '[1.0000000000000002,0.1]', 123);
    INSERT INTO memory_index_chunk_provenance VALUES('logical-id', 'owner', 'interactive', 122, 'prior-id');
    INSERT INTO memory_embedding_cache(rowid, provider, model, provider_key, hash, embedding, dims, updated_at)
      VALUES(23, 'provider', 'model', 'provider-key', 'h', '[1.0000000000000002,0.1]', 2, 121);
    INSERT INTO memory_index_chunks_fts(rowid, text, id, path, source, model, start_line, end_line)
      VALUES(99, 'saffronquasar', 'logical-id', 'memory/a.md', 'memory', 'model', 1, 2);
  `);
  return db;
}

function snapshot(db: DatabaseSync) {
  return {
    schema: db
      .prepare("SELECT type, name, tbl_name, sql FROM sqlite_schema ORDER BY type, name")
      .all(),
    chunks: db.prepare("SELECT rowid AS rowid, * FROM memory_index_chunks").all(),
    cache: db.prepare("SELECT rowid AS rowid, * FROM memory_embedding_cache").all(),
    sources: db.prepare("SELECT * FROM memory_index_sources").all(),
    meta: db.prepare("SELECT * FROM memory_index_meta").all(),
    provenance: db.prepare("SELECT * FROM memory_index_chunk_provenance").all(),
    fts: db.prepare("SELECT rowid, * FROM memory_index_chunks_fts").all(),
    foreignKeys: db.prepare("PRAGMA foreign_keys").get(),
  };
}

describe("memory storage migration", () => {
  describe.each(["TEXT", "ANY"] as const)("historical %s cache index", (embeddingType) => {
    const indexName = "idx_memory_embedding_cache_model_hash";
    const indexSql = `CREATE INDEX ${indexName} ON memory_embedding_cache(model, hash)`;

    it("preserves the optional model/hash index, cache identity, and nonunique semantics", () => {
      const db = legacyDatabase(embeddingType);
      db.exec(indexSql);
      // The index is deliberately nonunique: different providers can share both keys.
      db.exec(`INSERT INTO memory_embedding_cache
        SELECT 'other-provider', model, provider_key, hash, embedding, dims, updated_at
        FROM memory_embedding_cache`);
      const identities = db
        .prepare(`SELECT rowid, provider, model, provider_key, hash, dims,
        updated_at FROM memory_embedding_cache ORDER BY rowid`)
        .all();
      const terms = db.prepare(`PRAGMA index_xinfo(${indexName})`).all();
      const before = snapshot(db);
      assertMemoryIndexStorageMigrationCompatible(db);
      expect(snapshot(db)).toEqual(before);

      migrateMemoryIndexStorage(db);

      expect(db.prepare("SELECT sql FROM sqlite_schema WHERE name = ?").get(indexName)).toEqual({
        sql: indexSql,
      });
      expect(db.prepare(`PRAGMA index_xinfo(${indexName})`).all()).toEqual(terms);
      expect(
        db
          .prepare(`SELECT rowid, provider, model, provider_key, hash, dims,
        updated_at FROM memory_embedding_cache ORDER BY rowid`)
          .all(),
      ).toEqual(identities);
      expect(db.prepare("SELECT embedding FROM memory_embedding_cache").all()).toEqual([
        { embedding: encodeMemoryEmbedding([1 + Number.EPSILON, 0.1]) },
        { embedding: encodeMemoryEmbedding([1 + Number.EPSILON, 0.1]) },
      ]);
      expect(db.prepare("PRAGMA integrity_check").get()).toEqual({ integrity_check: "ok" });
      const migrated = snapshot(db);
      migrateMemoryIndexStorage(db);
      expect(snapshot(db)).toEqual(migrated);
    });

    it("leaves the optional index absent when it was not installed", () => {
      const db = legacyDatabase(embeddingType);
      migrateMemoryIndexStorage(db);
      expect(
        db.prepare("SELECT name FROM sqlite_schema WHERE name = ?").get(indexName),
      ).toBeUndefined();
    });

    it.each([
      `CREATE UNIQUE INDEX ${indexName} ON memory_embedding_cache(model, hash)`,
      `${indexSql} WHERE dims IS NOT NULL`,
      `CREATE INDEX ${indexName} ON memory_embedding_cache(hash, model)`,
      `CREATE INDEX ${indexName} ON memory_embedding_cache(lower(model), hash)`,
      `CREATE INDEX ${indexName} ON memory_embedding_cache(model COLLATE NOCASE, hash)`,
      `CREATE INDEX ${indexName} ON memory_embedding_cache(model DESC, hash)`,
      `CREATE INDEX ${indexName} ON memory_embedding_cache(model, hash, updated_at)`,
      `CREATE INDEX ${indexName} ON memory_index_chunks(model, hash)`,
      "CREATE INDEX operator_model_hash ON memory_embedding_cache(model, hash)",
    ])("refuses altered or unknown definitions atomically: %s", (sql) => {
      const db = legacyDatabase(embeddingType);
      db.exec(sql);
      const before = snapshot(db);
      for (const operation of [
        assertMemoryIndexStorageMigrationCompatible,
        migrateMemoryIndexStorage,
      ]) {
        expect(() => operation(db)).toThrow(/unknown index|missing or drifted index/);
        expect(snapshot(db)).toEqual(before);
      }
    });
  });

  it("migrates historical ANY JSON and Float32 values into canonical Float64 storage", () => {
    const db = legacyDatabase("ANY");
    const before = snapshot(db);
    // Frozen little-endian Float32 bytes, including a length divisible by eight.
    const cases = [
      { hex: "0000803f0000003f", values: [1, 0.5] },
      { hex: "cdcccc3d", values: [0.10000000149011612] },
      { hex: "0000008001000000", values: [-0, 1.401298464324817e-45] },
      { hex: "", values: [] },
    ];
    const insertChunk = db.prepare(`INSERT INTO memory_index_chunks
      SELECT ?, path, source, start_line, end_line, hash, model, text, ?, updated_at
      FROM memory_index_chunks WHERE id = 'logical-id'`);
    const insertCache = db.prepare(`INSERT INTO memory_embedding_cache
      SELECT provider, model, provider_key, ?, ?, ?, updated_at FROM memory_embedding_cache WHERE hash = 'h'`);
    for (const [index, item] of cases.entries()) {
      const bytes = Buffer.from(item.hex, "hex");
      insertChunk.run(`binary-${index}`, bytes);
      insertCache.run(`binary-${index}`, bytes, item.values.length);
    }
    const identities = db
      .prepare("SELECT rowid, id, text, updated_at FROM memory_index_chunks ORDER BY id")
      .all();
    const cacheIdentity = db
      .prepare(
        "SELECT rowid, provider, model, provider_key, hash, dims, updated_at FROM memory_embedding_cache ORDER BY hash",
      )
      .all();
    migrateMemoryIndexStorage(db);
    expect(
      db
        .prepare(
          "SELECT chunk_rowid AS rowid, id, text, updated_at FROM memory_index_chunks ORDER BY id",
        )
        .all(),
    ).toEqual(identities);
    expect(
      db
        .prepare(
          "SELECT rowid, provider, model, provider_key, hash, dims, updated_at FROM memory_embedding_cache ORDER BY hash",
        )
        .all(),
    ).toEqual(cacheIdentity);
    for (const [index, item] of cases.entries()) {
      for (const [table, key] of [
        ["memory_index_chunks", "id"],
        ["memory_embedding_cache", "hash"],
      ]) {
        const row = db
          .prepare(`SELECT embedding FROM ${table} WHERE ${key} = ?`)
          .get(`binary-${index}`)!;
        if (!(row.embedding instanceof Uint8Array)) {
          throw new Error("Expected canonical binary embedding");
        }
        expect(decodeMemoryEmbedding(row.embedding)).toEqual(item.values);
        expect(row.embedding.byteLength).toBe(item.values.length * 8);
      }
    }
    const text = db
      .prepare("SELECT embedding FROM memory_index_chunks WHERE id = 'logical-id'")
      .get()!;
    if (!(text.embedding instanceof Uint8Array)) {
      throw new Error("Expected canonical binary embedding");
    }
    expect(decodeMemoryEmbedding(text.embedding)).toEqual([1 + Number.EPSILON, 0.1]);
    for (const table of ["memory_index_chunks", "memory_embedding_cache"]) {
      expect(
        db.prepare(`SELECT type FROM pragma_table_info('${table}') WHERE name = 'embedding'`).get(),
      ).toEqual({ type: "BLOB" });
    }
    expect(db.prepare("SELECT * FROM memory_index_chunk_provenance").all()).toEqual(
      before.provenance,
    );
    expect(db.prepare("SELECT * FROM memory_index_meta").all()).toEqual(before.meta);
    expect(db.prepare("PRAGMA foreign_key_check").all()).toEqual([]);
    expect(db.prepare("PRAGMA integrity_check").get()).toEqual({ integrity_check: "ok" });
    const migrated = snapshot(db);
    migrateMemoryIndexStorage(db);
    expect(snapshot(db)).toEqual(migrated);
  });

  it.each([
    42,
    1.25,
    Buffer.from("01", "hex"),
    Buffer.from("0000807f", "hex"),
    Buffer.from("0000c07f", "hex"),
  ])("refuses unsupported ANY values without changing data or schema", (embedding) => {
    const db = legacyDatabase("ANY");
    db.prepare("UPDATE memory_embedding_cache SET embedding = ?").run(embedding);
    const before = snapshot(db);
    expect(() => migrateMemoryIndexStorage(db)).toThrow(/historical.*embedding/i);
    expect(snapshot(db)).toEqual(before);
  });

  it("converts vectors without providers and preserves identity, provenance, cache age, and FTS maintenance", () => {
    const db = legacyDatabase();
    migrateMemoryIndexStorage(db);
    const chunk = db
      .prepare("SELECT chunk_rowid, id, text, embedding, updated_at FROM memory_index_chunks")
      .get()!;
    expect(chunk).toMatchObject({
      chunk_rowid: 7,
      id: "logical-id",
      text: "saffronquasar",
      updated_at: 123,
    });
    expect(chunk.embedding).toBeInstanceOf(Uint8Array);
    if (!(chunk.embedding instanceof Uint8Array)) {
      throw new Error("Expected binary embedding");
    }
    expect(decodeMemoryEmbedding(chunk.embedding)).toEqual([1 + Number.EPSILON, 0.1]);
    expect(db.prepare("SELECT * FROM memory_index_chunk_provenance").get()).toMatchObject({
      chunk_id: "logical-id",
      origin_class: "owner",
      supersedes_key: "prior-id",
    });
    expect(
      db
        .prepare(
          "SELECT rowid, provider, model, provider_key, hash, dims, updated_at FROM memory_embedding_cache",
        )
        .get(),
    ).toEqual({
      rowid: 23,
      provider: "provider",
      model: "model",
      provider_key: "provider-key",
      hash: "h",
      dims: 2,
      updated_at: 121,
    });
    expect(
      db
        .prepare(
          "SELECT rowid, id FROM memory_index_chunks_fts WHERE memory_index_chunks_fts MATCH 'saffronquasar'",
        )
        .get(),
    ).toEqual({ rowid: 7, id: "logical-id" });
    migrateMemoryIndexStorage(db);
    db.exec("VACUUM; UPDATE memory_index_chunks SET text = 'ambercomet' WHERE id = 'logical-id'");
    expect(
      db
        .prepare(
          "SELECT rowid FROM memory_index_chunks_fts WHERE memory_index_chunks_fts MATCH 'ambercomet'",
        )
        .get(),
    ).toEqual({ rowid: 7 });
    expect(
      db
        .prepare(
          "SELECT 1 FROM memory_index_chunks_fts WHERE memory_index_chunks_fts MATCH 'saffronquasar'",
        )
        .get(),
    ).toBeUndefined();
    expect(db.prepare("PRAGMA foreign_keys").get()).toEqual({ foreign_keys: 1 });
    expect(db.prepare("PRAGMA foreign_key_check").all()).toEqual([]);
  });

  it.each(["TEXT", "ANY"] as const)(
    "retains malformed %s JSON text and provenance while recording regeneration debt",
    (embeddingType) => {
      const db = legacyDatabase(embeddingType);
      db.exec(
        "UPDATE memory_index_chunks SET embedding = '[1,null]'; UPDATE memory_embedding_cache SET embedding = 'invalid'",
      );
      migrateMemoryIndexStorage(db);
      expect(
        db.prepare("SELECT text, length(embedding) AS bytes FROM memory_index_chunks").get(),
      ).toEqual({ text: "saffronquasar", bytes: 0 });
      expect(db.prepare("SELECT hash FROM memory_index_sources").get()).toEqual({ hash: "" });
      expect(
        db
          .prepare("SELECT value FROM memory_index_meta WHERE key = 'memory_vector_rebuild_v1'")
          .get(),
      ).toEqual({ value: "1" });
      expect(
        db.prepare("SELECT count(*) AS count FROM memory_index_chunk_provenance").get(),
      ).toEqual({ count: 1 });
      expect(
        db.prepare("SELECT length(embedding) AS bytes FROM memory_embedding_cache").get(),
      ).toEqual({ bytes: 0 });
    },
  );

  it("rolls physical changes back with its enclosing admitted migration", () => {
    const db = legacyDatabase();
    db.exec("PRAGMA foreign_keys = OFF; BEGIN IMMEDIATE");
    migrateMemoryIndexStorage(db);
    db.exec("ROLLBACK; PRAGMA foreign_keys = ON");
    expect(db.prepare("SELECT embedding FROM memory_index_chunks").get()).toEqual({
      embedding: "[1.0000000000000002,0.1]",
    });
    expect(
      db
        .prepare(
          "SELECT name FROM pragma_table_info('memory_index_chunks') WHERE name = 'chunk_rowid'",
        )
        .get(),
    ).toBeUndefined();
    expect(db.prepare("SELECT rowid FROM memory_index_chunks_fts").get()).toEqual({ rowid: 99 });
    expect(db.prepare("SELECT chunk_id FROM memory_index_chunk_provenance").get()).toEqual({
      chunk_id: "logical-id",
    });
    expect(db.prepare("PRAGMA foreign_key_check").all()).toEqual([]);
  });

  it.each([
    [
      "CREATE INDEX operator_chunk_text ON memory_index_chunks(text)",
      /unknown index operator_chunk_text/,
    ],
    [
      "CREATE INDEX operator_cache_age ON memory_embedding_cache(updated_at)",
      /unknown index operator_cache_age/,
    ],
    [
      "CREATE TRIGGER operator_chunk_audit AFTER UPDATE ON memory_index_chunks BEGIN SELECT 1; END",
      /unexpected trigger operator_chunk_audit/,
    ],
    [
      "CREATE VIEW operator_chunk_text AS SELECT text FROM memory_index_chunks",
      /unknown view operator_chunk_text/,
    ],
    [
      "CREATE TABLE operator_chunk_notes (chunk_id TEXT REFERENCES memory_index_chunks(id), note TEXT)",
      /unknown foreign key in operator_chunk_notes/,
    ],
    [
      "ALTER TABLE memory_index_chunks ADD COLUMN operator_note TEXT; UPDATE memory_index_chunks SET operator_note = 'preserve this note'",
      /column definitions differ for memory_index_chunks/,
    ],
    [
      "ALTER TABLE memory_embedding_cache ADD COLUMN operator_note TEXT; UPDATE memory_embedding_cache SET operator_note = 'preserve this cache note'",
      /column definitions differ for memory_embedding_cache/,
    ],
  ] as const)(
    "refuses unknown persisted data or dependencies without touching the original database: %s",
    (addition, refusal) => {
      const db = legacyDatabase();
      db.exec(addition);
      const before = snapshot(db);
      expect(() => migrateMemoryIndexStorage(db)).toThrow(refusal);
      expect(snapshot(db)).toEqual(before);
      expect(
        db.prepare("SELECT name FROM sqlite_schema WHERE name LIKE '%storage_migration%'").all(),
      ).toEqual([]);
    },
  );

  it.each([
    {
      schema: MEMORY_INDEX_CHUNKS_SCHEMA_SQL.replace("embedding BLOB", "embedding TEXT"),
      embedding: "[]",
      identityColumn: "chunk_rowid",
    },
    {
      schema: MEMORY_INDEX_CHUNKS_SCHEMA_SQL.replace(
        "chunk_rowid INTEGER PRIMARY KEY,",
        "",
      ).replace("id TEXT NOT NULL UNIQUE", "id TEXT PRIMARY KEY"),
      embedding: new Uint8Array(),
      identityColumn: "rowid",
    },
    {
      schema: MEMORY_INDEX_CHUNKS_SCHEMA_SQL.replace(
        "chunk_rowid INTEGER PRIMARY KEY",
        "chunk_rowid INTEGER PRIMARY KEY DESC",
      ),
      embedding: new Uint8Array(),
      identityColumn: "chunk_rowid",
    },
  ])(
    "refuses mixed identity/format declarations instead of declaring conversion complete",
    ({ schema, embedding, identityColumn }) => {
      const db = legacyDatabase();
      db.exec("PRAGMA foreign_keys = OFF; DROP TABLE memory_index_chunks");
      db.exec(schema);
      db.prepare(`INSERT INTO memory_index_chunks(${identityColumn}, id, path, source, start_line, end_line, hash, model, text, embedding, updated_at)
      VALUES(7, 'logical-id', 'memory/a.md', 'memory', 1, 2, 'h', 'model', 'saffronquasar', ?, 123)`).run(
        embedding,
      );
      db.exec("PRAGMA foreign_keys = ON");
      const before = snapshot(db);
      expect(() => migrateMemoryIndexStorage(db)).toThrow(/partial memory storage|noncanonical/);
      expect(snapshot(db)).toEqual(before);
    },
  );

  it.each([new Uint8Array([1]), new Uint8Array(Buffer.from("000000000000f87f", "hex"))])(
    "refuses malformed preexisting binary cache rows while a chunk conversion is pending",
    (embedding) => {
      const db = legacyDatabase();
      db.exec("DROP TABLE memory_embedding_cache");
      db.exec(buildMemoryEmbeddingCacheSchema("memory_embedding_cache"));
      db.prepare(
        "INSERT INTO memory_embedding_cache VALUES('provider', 'model', 'provider-key', 'h', ?, 2, 121)",
      ).run(embedding);
      const before = snapshot(db);
      expect(() => migrateMemoryIndexStorage(db)).toThrow("invalid binary embeddings");
      expect(snapshot(db)).toEqual(before);
    },
  );

  it("validates an already-binary cache before completing the remaining chunk migration", () => {
    const db = legacyDatabase();
    db.exec("DROP TABLE memory_embedding_cache");
    db.exec(buildMemoryEmbeddingCacheSchema("memory_embedding_cache"));
    db.exec("ALTER TABLE memory_embedding_cache ADD COLUMN retained_note TEXT");
    const embedding = encodeMemoryEmbedding([1 + Number.EPSILON, 0.1]);
    db.prepare(
      "INSERT INTO memory_embedding_cache VALUES('provider', 'model', 'provider-key', 'h', ?, 2, 121, 'current format extension')",
    ).run(embedding);
    migrateMemoryIndexStorage(db);
    expect(db.prepare("SELECT embedding, retained_note FROM memory_embedding_cache").get()).toEqual(
      { embedding, retained_note: "current format extension" },
    );
    expect(
      db.prepare("SELECT chunk_rowid, typeof(embedding) AS kind FROM memory_index_chunks").get(),
    ).toEqual({ chunk_rowid: 7, kind: "blob" });
  });

  it("refuses malformed binary chunks before converting a remaining legacy cache", () => {
    const db = legacyDatabase();
    db.exec("PRAGMA foreign_keys = OFF; DROP TABLE memory_index_chunks");
    db.exec(MEMORY_INDEX_CHUNKS_SCHEMA_SQL);
    db.exec(`INSERT INTO memory_index_chunks(id, path, source, start_line, end_line, hash, model, text, embedding, updated_at)
      VALUES('logical-id', 'memory/a.md', 'memory', 1, 2, 'h', 'model', 'saffronquasar', X'01', 123)`);
    db.exec("PRAGMA foreign_keys = ON");
    const before = snapshot(db);
    expect(() => migrateMemoryIndexStorage(db)).toThrow("invalid binary embeddings");
    expect(snapshot(db)).toEqual(before);
  });

  it("preserves existing revision triggers and indexes without relying on the outer schema ensure", () => {
    const db = legacyDatabase();
    db.exec(`
      CREATE TABLE memory_index_state (id INTEGER PRIMARY KEY CHECK(id = 1), revision INTEGER NOT NULL) STRICT;
      INSERT INTO memory_index_state VALUES(1, 10);
      CREATE INDEX idx_memory_index_chunks_path_source ON memory_index_chunks(path, source);
      CREATE INDEX idx_memory_embedding_cache_updated_at ON memory_embedding_cache(updated_at);
    `);
    for (const event of ["insert", "update", "delete"]) {
      db.exec(`CREATE TRIGGER memory_index_chunks_revision_after_${event}
        AFTER ${event.toUpperCase()} ON memory_index_chunks
        BEGIN UPDATE memory_index_state SET revision = revision + 1 WHERE id = 1; END;`);
    }
    const indexes = db
      .prepare(
        "SELECT name, sql FROM sqlite_schema WHERE name IN ('idx_memory_index_chunks_path_source', 'idx_memory_embedding_cache_updated_at') ORDER BY name",
      )
      .all();
    migrateMemoryIndexStorage(db);
    expect(
      db
        .prepare(
          "SELECT name, sql FROM sqlite_schema WHERE name IN ('idx_memory_index_chunks_path_source', 'idx_memory_embedding_cache_updated_at') ORDER BY name",
        )
        .all(),
    ).toEqual(indexes);
    db.exec(
      "UPDATE memory_index_chunks SET text = 'new searchable text'; DELETE FROM memory_index_chunks",
    );
    expect(db.prepare("SELECT revision FROM memory_index_state").get()).toEqual({ revision: 12 });
  });

  it("renews long synchronous conversion work periodically and releases the callback afterward", () => {
    const db = legacyDatabase();
    const insert =
      db.prepare(`INSERT INTO memory_index_chunks(id, path, source, start_line, end_line, hash, model, text, embedding, updated_at)
      SELECT ?, path, source, start_line, end_line, hash, model, text, embedding, updated_at FROM memory_index_chunks WHERE id = 'logical-id'`);
    for (let index = 0; index < 10; index += 1) {
      insert.run(`extra-${index}`);
    }
    let clock = 0;
    const now = vi.spyOn(performance, "now").mockImplementation(() => (clock += 250));
    const renewals: number[] = [];
    try {
      migrateMemoryIndexStorage(db, { renewAuthority: () => renewals.push(clock) });
      expect(renewals.length).toBeGreaterThan(1);
      expect(
        renewals.every((instant, index) => index === 0 || instant - renewals[index - 1]! >= 1_000),
      ).toBe(true);
      const count = renewals.length;
      db.prepare("SELECT openclaw_memory_embedding_from_json(?)").get("[2]");
      expect(renewals).toHaveLength(count);
      expect(
        db
          .prepare(
            "SELECT count(*) AS count FROM memory_index_chunks WHERE typeof(embedding) = 'blob'",
          )
          .get(),
      ).toEqual({ count: 11 });
    } finally {
      now.mockRestore();
    }
  });

  it("rolls back admitted changes when authority is lost inside a conversion statement", () => {
    const db = legacyDatabase();
    db.exec("UPDATE memory_index_chunks SET embedding = '[1,null]'");
    const before = snapshot(db);
    let clock = 0;
    const now = vi.spyOn(performance, "now").mockImplementation(() => (clock += 1_000));
    let renewals = 0;
    try {
      expect(() =>
        migrateMemoryIndexStorage(db, {
          renewAuthority: () => {
            if (++renewals === 2) {
              throw new Error("migration authority revoked");
            }
          },
        }),
      ).toThrow();
      expect(renewals).toBe(2);
      expect(snapshot(db)).toEqual(before);
    } finally {
      now.mockRestore();
    }
  });
});
