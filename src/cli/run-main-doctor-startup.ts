import type { DoctorDatabasePreflight } from "../commands/doctor-database-preflight.js";

type DoctorCliStartup =
  | { handled: true }
  | { handled: false; preflight: DoctorDatabasePreflight | undefined };

export async function prepareDoctorCliStartup(
  argv: string[],
  options: { json: boolean },
): Promise<DoctorCliStartup> {
  if (process.env.OPENCLAW_UPDATE_POST_INSTALL_DOCTOR_RESULT_PATH?.trim() === "-") {
    // The native transport parent must not admit writers before its child owns Doctor.
    const { tryRunDoctorResultBridge } = await import("./run-main-doctor-result.js");
    if (await tryRunDoctorResultBridge(argv)) {
      return { handled: true };
    }
  }
  // Update-mode bootstrap can inspect SQLite before runDoctorHealthFlow starts.
  // Reject an invalid successor proof here as well, before that preflight.
  if (process.env.OPENCLAW_DOCTOR_BACKUP_REUSE_PROOF !== undefined) {
    const { parseReviewedDoctorBackupReuse } =
      await import("../commands/doctor-migration-backup-reuse.js");
    parseReviewedDoctorBackupReuse(process.env);
  }
  // Debug capture can migrate shared state before Commander reaches Doctor.
  // Resolve the update guard after selectors settle, before any bootstrap writer.
  const { preflightUpdateDoctorCli } = await import("../commands/doctor-update-schema-guard.js");
  return { handled: false, preflight: await preflightUpdateDoctorCli(options) };
}
