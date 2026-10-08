import { DatabaseSync } from "node:sqlite";
import { parentPort, threadId } from "node:worker_threads";

// A synthetic foreign writer changes real durable state. It does not implement
// or replace the product reconciler, reader, native broker, or commit receipts.
parentPort.on("message", ({ taskId, input }) => {
  const database = new DatabaseSync(input.path);
  try {
    database.exec("BEGIN IMMEDIATE");
    const result = database
      .prepare("UPDATE session_transcript_index_state SET needs_rebuild = 1 WHERE session_id = ?")
      .run(input.sessionId);
    database.exec("COMMIT");
    database.close();
    parentPort.postMessage(
      { status: "ok", taskId, value: { threadId, changed: Number(result.changes) } },
      [],
    );
  } catch (error) {
    try {
      if (database.isTransaction) {
        database.exec("ROLLBACK");
      }
      if (database.isOpen) {
        database.close();
      }
    } finally {
      parentPort.postMessage({ status: "failed", taskId, error: String(error) }, []);
    }
  }
});
