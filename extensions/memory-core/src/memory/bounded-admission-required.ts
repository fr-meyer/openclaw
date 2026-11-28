import type { DatabaseSync } from "node:sqlite";

// Supplied admitted canonical connection only. Never cache a negative result.
export function readBoundedMemoryRequirement(db: DatabaseSync, agentId: string): boolean {
  if (
    !db
      .prepare(
        "SELECT 1 FROM main.sqlite_schema WHERE type='table' AND name='memory_operation_owners'",
      )
      .get()
  ) {
    return false;
  }
  const row = db
    .prepare("SELECT required FROM main.memory_operation_owners WHERE agent=?")
    .get(agentId);
  if (row && row.required !== 0 && row.required !== 1) {
    throw new Error("Invalid bounded memory requirement");
  }
  return row?.required === 1;
}
