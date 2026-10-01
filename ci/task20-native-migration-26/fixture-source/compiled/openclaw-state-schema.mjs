import { readFileSync } from "node:fs";
export const OPENCLAW_STATE_SCHEMA_SQL=readFileSync(new URL("./openclaw-state-schema.sql",import.meta.url),"utf8");
