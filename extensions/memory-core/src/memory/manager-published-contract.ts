import type { DatabaseSync } from "node:sqlite";
import type { withOpenClawAgentDatabaseWrite } from "openclaw/plugin-sdk/sqlite-runtime";
import type { MemoryPublicationOperations } from "./manager-publication-task.js";

/** Minimal admitted published connection; the concrete owner retains all SQLite lifecycle gates. */
export type MemoryPublishedDatabase = {
  readonly db: DatabaseSync;
  readonly hasIndex: boolean;
  readonly fts: { enabled: boolean; available: boolean; loadError?: string };
  admitSchema(schema: MemoryPublicationOperations["schema.admit"]["input"]): Promise<void>;
  closePublicationWorker(): Promise<void>;
  release(): void;
};

export type MemoryPublishedOpenOptions = {
  agentId: string;
  writeOptions: Parameters<typeof withOpenClawAgentDatabaseWrite>[0] & { path: string };
  readOnly: boolean;
  allowExtension: boolean;
  maintenanceSource?: Pick<MemoryPublishedDatabase, "db" | "fts">;
  beforeSchema: (db: DatabaseSync) => void;
  schema: MemoryPublicationOperations["schema.admit"]["input"];
};

export type MemoryPublishedDatabaseConstructor<T extends MemoryPublishedDatabase> = new (
  db: DatabaseSync,
  release: () => void,
  readOnly: boolean,
  writeOptions: MemoryPublishedOpenOptions["writeOptions"],
  hasIndex: boolean,
) => T;
