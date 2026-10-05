/** Synthetic v2026.9.4 -> v2026.9.8 state/Workboard preservation fixture.
 * Prepare only on an approved, fsync-capable confined runner. No production input.
 */
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { backup, DatabaseSync } from "node:sqlite";
import { pathToFileURL } from "node:url";

const SCHEMA = "openclaw-parity-synthetic-fixture/v1";
const TIMESTAMP = 1_790_000_000_000;
const CARD_COUNT = 1081;
const SEED_PAGE_LIMITS = Object.freeze({ state: 512, workboard: 256 });
const PINS = Object.freeze({
  stateSql: "32a9ec60e38f1511e6f5fcd532f4c631d680d537a8325601f5bdf8221cf20fa3",
  workboardSource: "aa15bf48dbe292993a47c7286d5f7e12fe2ffbd74442c92b37ad98018bd2e810",
  controllerSource: "c3d63b3c567541f72fb33c6982b41d4d5e4efa7fdd2d43ba5d7d14e624ebdbfc",
});
const STATE_TABLES = ["flow_runs", "task_runs", "task_delivery_state", "subagent_runs"];
const WORKBOARD_TABLES = [
  "workboard_schema_migrations", "workboard_boards", "workboard_cards",
  "workboard_card_labels", "workboard_card_events", "workboard_card_attempts",
  "workboard_card_comments", "workboard_card_links", "workboard_card_proof",
  "workboard_card_artifacts", "workboard_card_diagnostics",
  "workboard_card_notifications", "workboard_worker_logs", "workboard_worker_protocol",
  "workboard_card_attachments", "workboard_attachment_blobs",
  "workboard_notification_subscriptions",
];
const FILES = [
  "state/openclaw.sqlite", "plugins/workboard/workboard.sqlite",
  "config.synthetic.json", "workspace/synthetic-marker.txt",
];
process.umask(0o077);

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function requirePinnedSource(sourcePath, expectedHash) {
  const bytes = fs.readFileSync(sourcePath);
  if (sha256(bytes) !== expectedHash) {
    throw new Error("SOURCE_PIN_MISMATCH");
  }
  return bytes.toString("utf8");
}

function requireFixtureRoot(root) {
  if (path.basename(root) !== "synthetic-parity-fixture") {
    throw new Error("FIXTURE_ROOT_BASENAME_REQUIRED");
  }
  const scratchRoot = process.env.PARITY_FIXTURE_SCRATCH_ROOT;
  if (!scratchRoot) {
    throw new Error("PARITY_FIXTURE_SCRATCH_ROOT_REQUIRED");
  }
  const resolved = path.resolve(root);
  if (path.dirname(resolved) !== fs.realpathSync(scratchRoot)) {
    throw new Error("FIXTURE_ROOT_OUTSIDE_SCRATCH");
  }
  if (fs.existsSync(resolved) && fs.lstatSync(resolved).isSymbolicLink()) {
    throw new Error("FIXTURE_ROOT_SYMLINK_REFUSED");
  }
  return resolved;
}

function workboardSqlFromSource(source) {
  const match = source.match(/const WORKBOARD_SCHEMA_SQL = `([\s\S]*?)`;/u);
  if (!match || match[1].includes("${")) {
    throw new Error("WORKBOARD_DDL_SOURCE_SHAPE_CHANGED");
  }
  return match[1];
}

function sqlitePath(root, phase, which) {
  return path.join(root, phase, which === "state"
    ? "state/openclaw.sqlite" : "plugins/workboard/workboard.sqlite");
}

function requireConsolidated(root, phase) {
  for (const which of ["state", "workboard"]) {
    const databasePath = sqlitePath(root, phase, which);
    for (const suffix of ["-wal", "-shm", "-journal"]) {
      if (readSidecarStat(databasePath + suffix)) {
        throw new Error(`UNSETTLED_SQLITE_SIDECAR:${which}:${suffix}`);
      }
    }
  }
}

function readSidecarStat(file) {
  try {
    return fs.lstatSync(file);
  } catch (error) {
    if (error.code === "ENOENT") return undefined;
    throw error;
  }
}

function readMainPin(file) {
  const fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  let result;
  let failure;
  try {
    const before = fs.fstatSync(fd);
    if (!before.isFile() || before.nlink !== 1 || before.uid !== 1000 || before.gid !== 1000) {
      throw new Error("READ_BOUNDARY_MAIN_IDENTITY_INVALID");
    }
    const digest = sha256(fs.readFileSync(fd));
    const after = fs.fstatSync(fd);
    for (const key of ["dev", "ino", "size", "uid", "gid", "nlink"]) {
      if (before[key] !== after[key]) throw new Error("READ_BOUNDARY_MAIN_CHANGED");
    }
    result = { file, dev: before.dev, ino: before.ino, size: before.size,
      uid: before.uid, gid: before.gid, nlink: before.nlink, sha256: digest };
  } catch (error) {
    failure = error;
  } finally {
    try {
      fs.closeSync(fd);
    } catch (error) {
      failure = failure ? new AggregateError([failure, error], "READ_BOUNDARY_FD_CLOSE_FAILED") : error;
    }
  }
  if (failure) throw failure;
  return result;
}

function captureReadBoundary(root, phase) {
  requireConsolidated(root, phase);
  const pins = ["state", "workboard"].map((which) => readMainPin(sqlitePath(root, phase, which)));
  requireConsolidated(root, phase);
  return pins;
}

function settleReadBoundary(root, phase, pins) {
  // Read-only WAL connections can leave empty coordination files. Only the
  // successfully closed, unchanged synthetic read scope may ask SQLite to
  // settle them; file deletion is never a substitute for SQLite close.
  if (pins.length !== 2 || pins.some((pin, index) =>
    pin.file !== sqlitePath(root, phase, index === 0 ? "state" : "workboard"))) {
    throw new Error("READ_BOUNDARY_PINS_INVALID");
  }
  const pending = [];
  for (const pin of pins) {
    if (JSON.stringify(readMainPin(pin.file)) !== JSON.stringify(pin)) {
      throw new Error("READ_BOUNDARY_MAIN_CHANGED");
    }
    const journal = readSidecarStat(pin.file + "-journal");
    const wal = readSidecarStat(pin.file + "-wal");
    const shm = readSidecarStat(pin.file + "-shm");
    if (journal || Boolean(wal) !== Boolean(shm)) throw new Error("READ_BOUNDARY_SIDECARS_UNEXPECTED");
    if (!wal) continue;
    for (const [sidecar, size] of [[wal, 0], [shm, 32768]]) {
      if (!sidecar.isFile() || sidecar.nlink !== 1 || sidecar.size !== size ||
          sidecar.dev !== pin.dev || sidecar.uid !== pin.uid || sidecar.gid !== pin.gid) {
        throw new Error("READ_BOUNDARY_SIDECARS_UNEXPECTED");
      }
    }
    pending.push({ pin, wal, shm });
  }
  for (const { pin, wal, shm } of pending) {
    if (JSON.stringify(readMainPin(pin.file)) !== JSON.stringify(pin)) throw new Error("READ_BOUNDARY_MAIN_CHANGED");
    for (const [suffix, expected] of [["-wal", wal], ["-shm", shm]]) {
      const actual = readSidecarStat(pin.file + suffix);
      if (!actual || !actual.isFile() || ["dev", "ino", "size", "uid", "gid", "nlink"].some((key) =>
        actual[key] !== expected[key])) throw new Error("READ_BOUNDARY_SIDECAR_CHANGED");
    }
    if (readSidecarStat(pin.file + "-journal")) throw new Error("READ_BOUNDARY_SIDECARS_UNEXPECTED");
    let owner;
    let failure;
    try {
      owner = new DatabaseSync(pin.file);
      const checkpoint = owner.prepare("PRAGMA wal_checkpoint(TRUNCATE)").get();
      if (checkpoint?.busy !== 0 || checkpoint.log !== 0 || checkpoint.checkpointed !== 0) {
        throw new Error("READ_BOUNDARY_CHECKPOINT_UNSETTLED");
      }
    } catch (error) {
      failure = error;
    } finally {
      try {
        owner?.close();
      } catch (error) {
        failure = failure ? new AggregateError([failure, error], "READ_BOUNDARY_OWNER_CLOSE_FAILED") : error;
      }
    }
    if (failure) throw failure;
    for (const suffix of ["-wal", "-shm", "-journal"]) {
      if (readSidecarStat(pin.file + suffix)) throw new Error("READ_BOUNDARY_OWNER_DID_NOT_SETTLE");
    }
    if (JSON.stringify(readMainPin(pin.file)) !== JSON.stringify(pin)) throw new Error("READ_BOUNDARY_MAIN_CHANGED");
  }
  requireConsolidated(root, phase);
  for (const pin of pins) {
    if (JSON.stringify(readMainPin(pin.file)) !== JSON.stringify(pin)) throw new Error("READ_BOUNDARY_MAIN_CHANGED");
  }
}

function rowDigest(database, table, columns) {
  if (!/^[a-z_]+$/u.test(table) || !columns.every((name) => /^[a-z_]+$/u.test(name))) {
    throw new Error("UNEXPECTED_IDENTIFIER");
  }
  const values = database.prepare(`SELECT ${columns.join(",")} FROM ${table}`).all();
  const normalized = values.map((row) => JSON.stringify(row, (_key, value) =>
    value instanceof Uint8Array ? { blobBase64: Buffer.from(value).toString("base64") } : value,
  )).sort();
  return { count: normalized.length, sha256: sha256(normalized.join("\n")) };
}

function columns(database, table) {
  return database.prepare(`PRAGMA table_info(${table})`).all().map((row) => row.name);
}

function captureTables(database, names) {
  return Object.fromEntries(names.map((table) => {
    const fields = columns(database, table);
    if (fields.length === 0) {
      throw new Error(`TABLE_MISSING:${table}`);
    }
    return [table, { columns: fields, ...rowDigest(database, table, fields) }];
  }));
}

function schemaDigest(database, names) {
  const definitions = names.map((table) => {
    const row = database.prepare(
      "SELECT sql FROM sqlite_master WHERE type='table' AND name=?",
    ).get(table);
    if (typeof row?.sql !== "string") {
      throw new Error(`TABLE_DEFINITION_MISSING:${table}`);
    }
    return `${table}:${row.sql.replace(/\s+/gu, " ").trim()}`;
  });
  const objects = database.prepare(`SELECT type,name,tbl_name,sql FROM sqlite_master
    WHERE type IN ('index','trigger','view')
      AND (substr(tbl_name,1,10)='workboard_' OR substr(name,1,10)='workboard_')
    ORDER BY type,name`).all().map((row) => JSON.stringify(row));
  return sha256([...definitions, ...objects].join("\n"));
}

function assertIntegrity(database) {
  const integrity = database.prepare("PRAGMA integrity_check").get();
  if (integrity?.integrity_check !== "ok") {
    throw new Error("SQLITE_INTEGRITY_FAILED");
  }
  if (database.prepare("PRAGMA foreign_key_check").all().length !== 0) {
    throw new Error("SQLITE_FOREIGN_KEY_FAILED");
  }
}

function closeDatabases(databases, primaryFailure) {
  const failures = [];
  for (const database of databases) {
    if (!database) {
      continue;
    }
    try {
      database.close();
    } catch (error) {
      failures.push(error);
    }
  }
  if (failures.length > 0) {
    if (primaryFailure !== undefined) failures.unshift(primaryFailure);
    throw new AggregateError(failures, "SYNTHETIC_DATABASE_CLOSE_FAILED");
  }
}

function seedDatabase(database, which, seed) {
  // Keep committed seed pages in WAL for the original backup path, while
  // avoiding one fsync/WAL rewrite per row. These limits apply only to the
  // invented raw seed; the candidate Doctor and its connection are unchanged.
  const pageLimit = SEED_PAGE_LIMITS[which];
  if (!pageLimit || database.isTransaction !== false) {
    throw new Error("INVALID_SEED_DATABASE");
  }
  database.exec("PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0; PRAGMA cache_spill=OFF;");
  if (database.prepare("PRAGMA foreign_keys").get()?.foreign_keys !== 1 ||
      database.prepare("PRAGMA journal_mode").get()?.journal_mode !== "wal" ||
      database.prepare("PRAGMA wal_autocheckpoint").get()?.wal_autocheckpoint !== 0 ||
      database.prepare("PRAGMA cache_spill").get()?.cache_spill !== 0 ||
      database.prepare("PRAGMA page_size").get()?.page_size !== 4096 ||
      database.prepare(`PRAGMA max_page_count=${pageLimit}`).get()?.max_page_count !== pageLimit) {
    throw new Error("SEED_STORAGE_PREREQUISITE_CHANGED");
  }
  database.exec("BEGIN IMMEDIATE");
  try {
    seed();
    database.exec("COMMIT");
    const pageCount = database.prepare("PRAGMA page_count").get()?.page_count;
    if (!Number.isSafeInteger(pageCount) || pageCount < 1 || pageCount > pageLimit) {
      throw new Error("SEED_PAGE_COUNT_OUTSIDE_LIMIT");
    }
    return { pageSize: 4096, pageCount, pageLimit };
  } catch (error) {
    // SQLITE_FULL may already have rolled back the transaction. Preserve that
    // primary failure instead of replacing it with "no transaction is active".
    if (database.isTransaction) {
      try {
        database.exec("ROLLBACK");
      } catch (rollbackError) {
        throw new AggregateError([error, rollbackError], "SEED_ROLLBACK_FAILED");
      }
    }
    throw error;
  }
}

function seedState(database, stateJson) {
  database.exec(stateJson.sql);
  database.prepare(`INSERT INTO schema_meta
    (meta_key,role,schema_version,agent_id,app_version,created_at,updated_at)
    VALUES ('primary','global',17,NULL,'2026.9.4',?,?)`).run(TIMESTAMP, TIMESTAMP);
  database.exec("PRAGMA user_version=17");
  const flowId = "synthetic-flow-001";
  const taskId = "synthetic-task-001";
  const runId = "synthetic-run-001";
  const owner = "agent:main:synthetic-publisher";
  database.prepare(`INSERT INTO flow_runs
    (flow_id,sync_mode,owner_key,controller_id,revision,status,notify_policy,goal,
     current_step,state_json,wait_json,created_at,updated_at)
    VALUES (?,'managed',?,'mergeguez-pr-lifecycle/v1',7,'blocked','none',
            'synthetic parity fixture','blocked',?,?,?,?)`)
    .run(flowId, owner, JSON.stringify(stateJson.blocked),
      JSON.stringify(stateJson.blocked.wait), TIMESTAMP, TIMESTAMP);
  database.prepare(`INSERT INTO task_runs
    (task_id,runtime,task_kind,requester_session_key,owner_key,scope_kind,
     child_session_key,parent_flow_id,run_id,agent_id,task,status,delivery_status,
     notify_policy,created_at,ended_at)
    VALUES (?,'subagent','review',?,?,'managed',?,?,?,'synthetic-worker',
            'synthetic review only','failed','not_requested','none',?,?)`)
    .run(taskId, owner, owner, "agent:main:subagent:synthetic", flowId, runId,
      TIMESTAMP, TIMESTAMP + 1);
  database.prepare(`INSERT INTO task_delivery_state
    (task_id,requester_origin_json,last_notified_event_at) VALUES (?,?,?)`)
    .run(taskId, JSON.stringify({ channel: "synthetic" }), TIMESTAMP);
  database.prepare(`INSERT INTO subagent_runs
    (run_id,child_session_key,requester_session_key,created_at,payload_json)
    VALUES (?,?,?,?,?)`)
    .run(runId, "agent:main:subagent:synthetic", owner, TIMESTAMP,
      JSON.stringify({ runId, childSessionKey: "agent:main:subagent:synthetic",
        requesterSessionKey: owner, task: "synthetic review only", createdAt: TIMESTAMP,
        execution: { status: "terminal" }, completion: { required: true },
        delivery: { status: "suspended", suspendedReason: "permanent_failure" } }));
}

function seedWorkboard(database, sql) {
  database.exec(sql);
  database.prepare("INSERT INTO workboard_schema_migrations VALUES ('schema-3',?)").run(TIMESTAMP);
  database.prepare(`INSERT INTO workboard_boards
    (id,name,created_at,updated_at) VALUES ('synthetic-board','Synthetic board',?,?)`)
    .run(TIMESTAMP, TIMESTAMP);
  const insert = database.prepare(`INSERT INTO workboard_cards
    (id,board_id,title,status,priority,position,created_at,updated_at,archived_at,
     session_key,run_id,execution_kind,execution_mode,execution_status)
    VALUES (?,'synthetic-board',? ,?,'normal',?,?,?, ?,?,?,?, ?,?)`);
  for (let index = 0; index < CARD_COUNT; index += 1) {
    const running = index < 9;
    insert.run(`synthetic-card-${String(index).padStart(4, "0")}`,
      `Synthetic card ${index}`, running ? "running" : "todo", index,
      TIMESTAMP, TIMESTAMP, index >= CARD_COUNT - 3 ? TIMESTAMP : null,
      running ? `agent:main:subagent:card-${index}` : null,
      running ? `synthetic-card-run-${index}` : null,
      running ? "agent-session" : null, running ? "autonomous" : null,
      running ? "running" : null);
  }
  const card = "synthetic-card-0000";
  const rows = [
    ["workboard_card_labels", "card_id,ordinal,label", [card, 0, "synthetic"]],
    ["workboard_card_events", "id,card_id,ordinal,kind,at", ["event-1", card, 0, "created", TIMESTAMP]],
    ["workboard_card_attempts", "id,card_id,ordinal,status,started_at", ["attempt-1", card, 0, "running", TIMESTAMP]],
    ["workboard_card_comments", "id,card_id,ordinal,body,created_at", ["comment-1", card, 0, "synthetic only", TIMESTAMP]],
    ["workboard_card_links", "id,card_id,ordinal,type,target_card_id,created_at", ["link-1", card, 0, "reference", "synthetic-card-0001", TIMESTAMP]],
    ["workboard_card_proof", "id,card_id,ordinal,status,created_at", ["proof-1", card, 0, "passed", TIMESTAMP]],
    ["workboard_card_artifacts", "id,card_id,ordinal,label,created_at", ["artifact-1", card, 0, "synthetic", TIMESTAMP]],
    ["workboard_card_diagnostics", "card_id,ordinal,kind,severity,title,detail,first_seen_at,last_seen_at,count,actions_json", [card, 0, "fixture", "info", "Synthetic", "Fixture only", TIMESTAMP, TIMESTAMP, 1, "[]"]],
    ["workboard_card_notifications", "id,card_id,ordinal,kind,message,created_at", ["notification-1", card, 0, "fixture", "synthetic", TIMESTAMP]],
    ["workboard_worker_logs", "id,card_id,ordinal,level,message,created_at", ["log-1", card, 0, "info", "synthetic", TIMESTAMP]],
    ["workboard_worker_protocol", "card_id,state,updated_at", [card, "idle", TIMESTAMP]],
    ["workboard_card_attachments", "id,card_id,ordinal,file_name,byte_size,created_at", ["attachment-1", card, 0, "synthetic.bin", 4, TIMESTAMP]],
    ["workboard_attachment_blobs", "attachment_id,content", ["attachment-1", Buffer.from("DATA")]],
    ["workboard_notification_subscriptions", "id,board_id,created_at,updated_at", ["subscription-1", "synthetic-board", TIMESTAMP, TIMESTAMP]],
  ];
  for (const [table, names, values] of rows) {
    database.prepare(`INSERT INTO ${table} (${names}) VALUES (${values.map(() => "?").join(",")})`)
      .run(...values);
  }
}

async function prepare(root, stateSqlPath, workboardSourcePath, controllerSourcePath) {
  if (fs.existsSync(root)) {
    throw new Error("FIXTURE_ROOT_MUST_BE_NEW");
  }
  const stateSql = requirePinnedSource(stateSqlPath, PINS.stateSql);
  const workboardSource = requirePinnedSource(workboardSourcePath, PINS.workboardSource);
  requirePinnedSource(controllerSourcePath, PINS.controllerSource);
  const { createState, blockState, isLifecycleState } = await import(pathToFileURL(controllerSourcePath).href);
  const state = createState({ action: "opened", eventId: "synthetic-opened",
    repo: "fixture/openclaw", prNumber: 1, headSha: "a".repeat(40),
    baseSha: "b".repeat(40), baseRef: "dev", headRepo: "fixture/openclaw" },
  { reviewActor: "mergeguez", authorActor: "le-commis", reviewWorkerAgentId: "synthetic-review",
    authorWorkerAgentId: "le-commis", workspace: "/synthetic/workspace",
    baseBranches: ["dev"], mode: "observe" }, TIMESTAMP);
  const blocked = blockState(state, "synthetic_manual_hold", TIMESTAMP + 1).state;
  if (!isLifecycleState(blocked) || blocked.phase !== "blocked") {
    throw new Error("SYNTHETIC_CONTROLLER_STATE_INVALID");
  }
  fs.mkdirSync(root, { recursive: false, mode: 0o700 });
  const raw = path.join(root, "raw");
  const predecessor = path.join(root, "predecessor");
  const candidate = path.join(root, "candidate");
  for (const phase of [raw, predecessor, candidate]) {
    fs.mkdirSync(path.join(phase, "state"), { recursive: true, mode: 0o700 });
    fs.mkdirSync(path.join(phase, "plugins/workboard"), { recursive: true, mode: 0o700 });
  }
  const stateDb = new DatabaseSync(sqlitePath(root, "raw", "state"));
  let workboardDb;
  const seedStorage = {};
  try {
    workboardDb = new DatabaseSync(sqlitePath(root, "raw", "workboard"));
    seedStorage.state = seedDatabase(stateDb, "state", () => seedState(stateDb, { sql: stateSql, blocked }));
    seedStorage.workboard = seedDatabase(workboardDb, "workboard", () => seedWorkboard(workboardDb, workboardSqlFromSource(workboardSource)));
    for (const which of ["state", "workboard"]) {
      const storage = seedStorage[which];
      const wal = fs.statSync(sqlitePath(root, "raw", which) + "-wal");
      const frameSize = storage.pageSize + 24;
      if (!wal.isFile() || wal.nlink !== 1 || wal.size < 32 + frameSize ||
          wal.size > 32 + storage.pageLimit * frameSize || (wal.size - 32) % frameSize !== 0) {
        throw new Error(`SEED_WAL_OUTSIDE_LIMIT:${which}`);
      }
      storage.walBytesBeforeBackup = wal.size;
    }
    await backup(stateDb, sqlitePath(root, "predecessor", "state"));
    await backup(workboardDb, sqlitePath(root, "predecessor", "workboard"));
  } finally {
    closeDatabases([workboardDb, stateDb]);
  }
  fs.writeFileSync(path.join(predecessor, "config.synthetic.json"),
    JSON.stringify({ plugins: { entries: { "mergeguez-pr-lifecycle": {
      enabled: true, config: { enabled: true, ownerSessionKey: "agent:main:synthetic-publisher" },
    }, workboard: { enabled: true } } } }) + "\n", { mode: 0o600 });
  fs.mkdirSync(path.join(predecessor, "workspace"), { mode: 0o700 });
  fs.writeFileSync(path.join(predecessor, "workspace/synthetic-marker.txt"), "synthetic workspace\n");
  for (const relative of FILES) {
    const destination = path.join(candidate, relative);
    fs.mkdirSync(path.dirname(destination), { recursive: true, mode: 0o700 });
    fs.copyFileSync(path.join(predecessor, relative), destination, fs.constants.COPYFILE_EXCL);
  }
  requireConsolidated(root, "predecessor");
  requireConsolidated(root, "candidate");
  const readBoundary = captureReadBoundary(root, "predecessor");
  const stateRead = new DatabaseSync(sqlitePath(root, "predecessor", "state"), { readOnly: true });
  let workboardRead;
  let manifest;
  let readFailure;
  try {
    workboardRead = new DatabaseSync(sqlitePath(root, "predecessor", "workboard"), { readOnly: true });
    assertIntegrity(stateRead);
    assertIntegrity(workboardRead);
    manifest = { schema: SCHEMA, syntheticOnly: true, sourcePins: PINS, seedStorage,
      predecessorStateVersion: 17, candidateStateVersion: 19,
      state: captureTables(stateRead, STATE_TABLES),
      workboard: captureTables(workboardRead, WORKBOARD_TABLES),
      workboardSchemaSha256: schemaDigest(workboardRead, WORKBOARD_TABLES),
      predecessorDbHashes: {
        state: sha256(fs.readFileSync(sqlitePath(root, "predecessor", "state"))),
        workboard: sha256(fs.readFileSync(sqlitePath(root, "predecessor", "workboard"))),
      },
      files: Object.fromEntries(FILES.filter((name) => !name.endsWith(".sqlite"))
        .map((name) => [name, sha256(fs.readFileSync(path.join(predecessor, name)))])) };
    fs.writeFileSync(path.join(root, "manifest.json"), JSON.stringify(manifest, null, 2) + "\n",
      { mode: 0o600 });
  } catch (error) {
    readFailure = error;
    throw error;
  } finally {
    closeDatabases([workboardRead, stateRead], readFailure);
  }
  settleReadBoundary(root, "predecessor", readBoundary);
  requireConsolidated(root, "predecessor");
  requireConsolidated(root, "candidate");
  for (const which of ["state", "workboard"]) {
    for (const phase of ["predecessor", "candidate"]) {
      if (sha256(fs.readFileSync(sqlitePath(root, phase, which))) !== manifest.predecessorDbHashes[which]) {
        throw new Error(`PREPARED_DATABASE_COPY_CHANGED:${phase}:${which}`);
      }
    }
  }
  // No assertion, migration or restore reads raw. Preserve it on every earlier
  // failure; successful preparation keeps the byte-pinned predecessor and the
  // independent candidate as the complete asserted inputs.
  fs.rmSync(raw, { recursive: true });
  process.stdout.write(JSON.stringify({ prepared: true, syntheticOnly: true, cards: CARD_COUNT }) + "\n");
}

function assertPhase(root, phase) {
  if (!new Set(["predecessor", "candidate", "rollback"]).has(phase)) {
    throw new Error("INVALID_PHASE");
  }
  const manifest = JSON.parse(fs.readFileSync(path.join(root, "manifest.json"), "utf8"));
  if (manifest.schema !== SCHEMA || manifest.syntheticOnly !== true) {
    throw new Error("FIXTURE_MANIFEST_INVALID");
  }
  requireConsolidated(root, phase);
  const readBoundary = captureReadBoundary(root, phase);
  const stateDb = new DatabaseSync(sqlitePath(root, phase, "state"), { readOnly: true });
  let workboardDb;
  let readFailure;
  try {
    workboardDb = new DatabaseSync(sqlitePath(root, phase, "workboard"), { readOnly: true });
    assertIntegrity(stateDb);
    assertIntegrity(workboardDb);
    const expectedVersion = phase === "candidate" ? 19 : 17;
    if (stateDb.prepare("PRAGMA user_version").get()?.user_version !== expectedVersion) {
      throw new Error("STATE_VERSION_MISMATCH");
    }
    const metadata = stateDb.prepare(
      "SELECT role,schema_version,agent_id FROM schema_meta WHERE meta_key='primary'",
    ).get();
    if (metadata?.role !== "global" || metadata.schema_version !== expectedVersion ||
        metadata.agent_id !== null) {
      throw new Error("STATE_METADATA_MISMATCH");
    }
    if (schemaDigest(workboardDb, WORKBOARD_TABLES) !== manifest.workboardSchemaSha256) {
      throw new Error("WORKBOARD_SCHEMA_CHANGED");
    }
    if (phase !== "candidate") {
      for (const which of ["state", "workboard"]) {
        if (sha256(fs.readFileSync(sqlitePath(root, phase, which))) !==
            manifest.predecessorDbHashes?.[which]) {
          throw new Error(`PREDECESSOR_BYTES_CHANGED:${which}`);
        }
      }
    }
    for (const [database, entries] of [[stateDb, manifest.state], [workboardDb, manifest.workboard]]) {
      for (const [table, expected] of Object.entries(entries)) {
        const actual = rowDigest(database, table, expected.columns);
        if (actual.count !== expected.count || actual.sha256 !== expected.sha256) {
          throw new Error(`ROW_PRESERVATION_FAILED:${table}`);
        }
      }
    }
    const flow = stateDb.prepare("SELECT controller_id,status FROM flow_runs WHERE flow_id='synthetic-flow-001'").get();
    if (flow?.controller_id !== "mergeguez-pr-lifecycle/v1" || flow.status !== "blocked") {
      throw new Error("PUBLISHER_BLOCKED_FLOW_CHANGED");
    }
    if (phase === "candidate") {
      const extraColumns = columns(stateDb, "subagent_runs");
      if (!extraColumns.includes("controller_store_path") || !extraColumns.includes("requester_store_path")) {
        throw new Error("CANDIDATE_SUBAGENT_SCHEMA_MISSING");
      }
    }
    for (const [name, expected] of Object.entries(manifest.files)) {
      if (sha256(fs.readFileSync(path.join(root, phase, name))) !== expected) {
        throw new Error(`FILE_PRESERVATION_FAILED:${name}`);
      }
    }
  } catch (error) {
    readFailure = error;
    throw error;
  } finally {
    closeDatabases([workboardDb, stateDb], readFailure);
  }
  settleReadBoundary(root, phase, readBoundary);
  process.stdout.write(JSON.stringify({ phase, rowsPreserved: true, syntheticOnly: true }) + "\n");
}

async function migrateCandidate(root, sourceModulePath, sourceModuleSha256) {
  const manifest = JSON.parse(fs.readFileSync(path.join(root, "manifest.json"), "utf8"));
  if (manifest.schema !== SCHEMA || manifest.syntheticOnly !== true) {
    throw new Error("FIXTURE_MANIFEST_INVALID");
  }
  requireConsolidated(root, "candidate");
  for (const which of ["state", "workboard"]) {
    if (sha256(fs.readFileSync(sqlitePath(root, "candidate", which))) !==
        manifest.predecessorDbHashes?.[which]) {
      throw new Error(`CANDIDATE_PREIMAGE_CHANGED:${which}`);
    }
  }
  if (!/^[a-f0-9]{64}$/u.test(sourceModuleSha256)) {
    throw new Error("SOURCE_SHA256_REQUIRED");
  }
  requirePinnedSource(sourceModulePath, sourceModuleSha256);
  const source = await import(pathToFileURL(sourceModulePath).href);
  if (typeof source.prepareOpenClawStateDatabaseSchema !== "function") {
    throw new Error("NATIVE_DOCTOR_MIGRATION_ENTRY_MISSING");
  }
  const candidateStatePath = sqlitePath(root, "candidate", "state");
  const result = await source.prepareOpenClawStateDatabaseSchema(
    { path: candidateStatePath, env: { OPENCLAW_STATE_DIR: path.dirname(candidateStatePath) } },
    "doctor",
  );
  assertPhase(root, "predecessor");
  if (sha256(fs.readFileSync(sqlitePath(root, "candidate", "workboard"))) !==
      manifest.predecessorDbHashes.workboard) {
    throw new Error("WORKBOARD_BYTES_CHANGED_BY_STATE_MIGRATION");
  }
  assertPhase(root, "candidate");
  process.stdout.write(JSON.stringify({ migrated: true, syntheticOnly: true,
    nativeDoctorChanges: result.changes.length, nativeDoctorWarnings: result.warnings.length }) + "\n");
}

function restore(root) {
  assertPhase(root, "predecessor");
  const destination = path.join(root, "rollback");
  const manifest = JSON.parse(fs.readFileSync(path.join(root, "manifest.json"), "utf8"));
  if (manifest.schema !== SCHEMA || manifest.syntheticOnly !== true) {
    throw new Error("FIXTURE_MANIFEST_INVALID");
  }
  if (fs.existsSync(destination)) {
    throw new Error("ROLLBACK_DESTINATION_MUST_BE_NEW");
  }
  fs.mkdirSync(destination, { mode: 0o700 });
  for (const relative of FILES) {
    const target = path.join(destination, relative);
    fs.mkdirSync(path.dirname(target), { recursive: true, mode: 0o700 });
    fs.copyFileSync(path.join(root, "predecessor", relative), target, fs.constants.COPYFILE_EXCL);
  }
  assertPhase(root, "rollback");
}

const [command, untrustedRoot, ...args] = process.argv.slice(2);
if (!command || !untrustedRoot) {
  throw new Error("USAGE: fixture.mjs prepare|migrate|assert|restore <synthetic-parity-fixture-path> [source paths, source module/hash, or phase]");
}
const root = requireFixtureRoot(untrustedRoot);
if (command === "prepare" && args.length === 3) {
  await prepare(root, ...args);
} else if (command === "migrate" && args.length === 2) {
  await migrateCandidate(root, ...args);
} else if (command === "assert" && args.length === 1) {
  assertPhase(root, args[0]);
} else if (command === "restore" && args.length === 0) {
  restore(root);
} else {
  throw new Error("INVALID_FIXTURE_COMMAND");
}
