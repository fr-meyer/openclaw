import type {
  MemoryPublishedDatabase,
  MemoryPublishedDatabaseConstructor,
  MemoryPublishedOpenOptions,
} from "./manager-published-contract.js";
export type { MemoryPublishedOpenOptions } from "./manager-published-contract.js";
import { MEMORY_INDEX_FTS_TABLE } from "openclaw/plugin-sdk/memory-core-host-engine-storage";
import {
  borrowOpenClawAgentDatabase,
  withOpenClawAgentDatabaseWrite,
} from "openclaw/plugin-sdk/sqlite-runtime";
import { memoryDatabaseTableExists } from "./manager-db-kernel.js";
import { openMemoryDatabaseReadOnlyAtPath } from "./manager-db.js";

export async function openPublishedMemoryDatabase<T extends MemoryPublishedDatabase>(
  Database: MemoryPublishedDatabaseConstructor<T>,
  params: MemoryPublishedOpenOptions,
): Promise<T> {
  const connection = params.readOnly
    ? openMemoryDatabaseReadOnlyAtPath(
        params.writeOptions.path,
        params.allowExtension,
        params.agentId,
        params.beforeSchema,
        params.writeOptions.env,
      )
    : await withOpenClawAgentDatabaseWrite(
        params.writeOptions,
        ({ db }) => {
          // Actual admitted connection, before borrowing, schema, or provider work.
          params.beforeSchema(db);
          return { ...borrowOpenClawAgentDatabase(params.writeOptions), hasIndex: true };
        },
        params.maintenanceSource?.db,
      );
  if (params.maintenanceSource && connection.db !== params.maintenanceSource.db) {
    connection.release();
    throw new Error("Memory maintenance source connection changed");
  }
  const database = new Database(
    connection.db,
    connection.release,
    params.readOnly,
    params.writeOptions,
    connection.hasIndex,
  );
  try {
    database.fts.enabled = params.schema.ftsEnabled;
    if (
      params.maintenanceSource &&
      (!database.fts.enabled || params.maintenanceSource.fts.available)
    ) {
      Object.assign(database.fts, params.maintenanceSource.fts);
    } else if (params.readOnly) {
      database.fts.available =
        database.hasIndex &&
        database.fts.enabled &&
        memoryDatabaseTableExists(database.db, "main", MEMORY_INDEX_FTS_TABLE);
    } else {
      await database.admitSchema(params.schema);
      // Sync must acquire its own retained executor for accepted shutdown work.
      await database.closePublicationWorker();
    }
    return database;
  } catch (error) {
    // Failed worker cleanup retains its own borrow with the agent lifecycle.
    database.release();
    throw error;
  }
}
