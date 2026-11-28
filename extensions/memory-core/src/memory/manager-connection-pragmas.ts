import type { DatabaseSync } from "node:sqlite";
import type { MemoryPublicationConnection } from "./manager-publication-task.js";

export function readConnectionPragmas(db: DatabaseSync, errorMessage: string) {
  const read = (name: keyof MemoryPublicationConnection["pragmas"]): number => {
    const row = db.prepare(`PRAGMA ${name}`).get();
    const value = row?.[name] ?? row?.timeout;
    if (typeof value !== "number" || !Number.isSafeInteger(value)) {
      throw new Error(errorMessage);
    }
    return value;
  };
  return {
    busy_timeout: read("busy_timeout"),
    synchronous: read("synchronous"),
    foreign_keys: read("foreign_keys"),
    journal_size_limit: read("journal_size_limit"),
    checkpoint_fullfsync: read("checkpoint_fullfsync"),
  };
}
