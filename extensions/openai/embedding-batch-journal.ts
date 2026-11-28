import { Worker } from "node:worker_threads";

/** Supplied by the independent migration controller, never inferred from API keys. */
export type OpenAiBatchJournalContext = {
  path: string;
  migrationId: string;
  sourceRevision: string;
  accountId: string;
  route: string;
};

export type OpenAiDurableBatchReceipt = {
  operationId: string;
  identity: string;
  phase: "upload-unknown" | "upload-rejected" | "create-unknown" | "accepted";
  inputFileId?: string;
  batchId?: string;
};

// SQLite runs in a worker, not on the Gateway thread. The controller provisions
// a private directory and owns retention. No existing agent database is opened.
const workerSource = String.raw`import { parentPort, workerData as p } from "node:worker_threads";
import { DatabaseSync } from "node:sqlite";
import fs from "node:fs";
import path from "node:path";
let db;
try {
  if (!path.isAbsolute(p.path)) throw new Error("Batch journal path must be absolute");
  try { fs.closeSync(fs.openSync(p.path, "ax", 0o600)); }
  catch (error) { if (error.code !== "EEXIST") throw error; }
  const stat = fs.lstatSync(p.path);
  if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o077)) {
    throw new Error("Batch journal must be a private regular file");
  }
  // This is a dedicated receipt lock primitive, not an application DB writer.
  // Refuse unrelated existing databases before any SQLite write or PRAGMA change.
  const applicationId = 0x4f414249;
  if (stat.size > 0) {
    const header = Buffer.alloc(100);
    const file = fs.openSync(p.path, "r");
    try { fs.readSync(file, header, 0, header.length, 0); } finally { fs.closeSync(file); }
    if (header.toString("utf8", 0, 16) !== "SQLite format 3\0" || header.readUInt32BE(68) !== applicationId) {
      throw new Error("Refusing unrelated or incomplete Batch journal database");
    }
  }
  db = new DatabaseSync(p.path);
  if (stat.size === 0) db.exec("PRAGMA application_id=" + applicationId);
  db.exec("PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA busy_timeout=0");
  db.exec("CREATE TABLE IF NOT EXISTS batch_intents (operation TEXT PRIMARY KEY, identity TEXT NOT NULL, phase TEXT NOT NULL, input_file TEXT, batch_id TEXT)");
  db.exec("BEGIN IMMEDIATE");
  const inserted = db.prepare("INSERT OR IGNORE INTO batch_intents VALUES (?, ?, 'upload-unknown', NULL, NULL)").run(p.operationId, p.identity).changes === 1;
  let row = db.prepare("SELECT * FROM batch_intents WHERE operation=?").get(p.operationId);
  if (!row || row.identity !== p.identity) throw new Error("Batch journal identity mismatch");
  if (p.rejectedUpload) {
    if (row.phase !== "upload-unknown" || row.input_file || row.batch_id || p.transition) {
      throw new Error("Invalid upload rejection transition");
    }
    db.prepare("UPDATE batch_intents SET phase='upload-rejected' WHERE operation=?").run(p.operationId);
    row = db.prepare("SELECT * FROM batch_intents WHERE operation=?").get(p.operationId);
  }
  if (p.transition) {
    const t = p.transition;
    if (!t.inputFileId || (row.input_file && row.input_file !== t.inputFileId)) throw new Error("Batch journal file mismatch");
    if (row.batch_id && row.batch_id !== t.batchId) throw new Error("Batch journal accepted ID mismatch");
    if (row.phase === "accepted" && !t.batchId) throw new Error("Batch journal cannot regress acceptance");
    db.prepare("UPDATE batch_intents SET phase=?, input_file=?, batch_id=? WHERE operation=?").run(t.batchId ? "accepted" : "create-unknown", t.inputFileId, t.batchId ?? null, p.operationId);
    row = db.prepare("SELECT * FROM batch_intents WHERE operation=?").get(p.operationId);
  }
  db.exec("COMMIT");
  db.close(); db = undefined;
  // SQLite FULL commits the database; additionally persist initial directory entry.
  const directory = fs.openSync(path.dirname(p.path), "r");
  try { fs.fsyncSync(directory); } finally { fs.closeSync(directory); }
  parentPort.postMessage({ result: { inserted, receipt: {
    operationId: row.operation, identity: row.identity, phase: row.phase,
    ...(row.input_file ? { inputFileId: row.input_file } : {}),
    ...(row.batch_id ? { batchId: row.batch_id } : {}),
  } } });
} catch (error) {
  parentPort.postMessage({ error: String(error) });
} finally { if (db) db.close(); }
`;

const journalTails = new Map<string, Promise<void>>();

export async function updateOpenAiBatchJournal(params: {
  path: string;
  operationId: string;
  identity: string;
  transition?: { inputFileId: string; batchId?: string };
  rejectedUpload?: boolean;
}): Promise<{ inserted: boolean; receipt: OpenAiDurableBatchReceipt }> {
  // Native Batch groups may run concurrently; this one receipt owner serializes
  // only its own local transactions, never uploads/polls or unrelated paths.
  const previous = journalTails.get(params.path) ?? Promise.resolve();
  const work = previous.then(() => runJournalWorker(params));
  const tail = work.then(
    () => {},
    () => {},
  );
  journalTails.set(params.path, tail);
  try {
    return await work;
  } finally {
    if (journalTails.get(params.path) === tail) journalTails.delete(params.path);
  }
}

async function runJournalWorker(params: {
  path: string;
  operationId: string;
  identity: string;
  transition?: { inputFileId: string; batchId?: string };
  rejectedUpload?: boolean;
}): Promise<{ inserted: boolean; receipt: OpenAiDurableBatchReceipt }> {
  return await new Promise((resolve, reject) => {
    const worker = new Worker(new URL("data:text/javascript," + encodeURIComponent(workerSource)), {
      workerData: params,
    });
    let result: { inserted: boolean; receipt: OpenAiDurableBatchReceipt } | undefined;
    let failure: Error | undefined;
    worker.once("message", (message: { result?: typeof result; error?: string }) => {
      result = message.result;
      if (message.error) {
        failure = new Error(message.error);
      }
    });
    worker.once("error", (error: unknown) => {
      failure =
        error instanceof Error
          ? error
          : new Error("OpenAI Batch journal worker failed", { cause: error });
    });
    worker.once("exit", (code) => {
      if (failure || code !== 0 || !result) {
        reject(failure ?? new Error("OpenAI Batch journal worker exited without a receipt"));
      } else {
        resolve(result);
      }
    });
  });
}
