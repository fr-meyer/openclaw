/**
 * Runtime SDK subpath for config file writes and mutation helpers.
 */
export { logConfigUpdated } from "../config/logging.js";
export { readConfigFileSnapshotForWrite } from "../config/io.js";
export { mutateConfigFile, replaceConfigFile } from "../config/mutate.js";
export type { ConfigWriteAfterWrite } from "../config/runtime-snapshot.js";
export { updateConfig } from "../commands/models/shared.js";

/** Feature negotiation only; evaluated SDK custody remains the caller's responsibility. */
export const CONFIG_MUTATION_CAPABILITIES = Object.freeze({ requireDurableBackup: 1 as const });
