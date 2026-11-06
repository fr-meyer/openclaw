import fs from "node:fs";
import path from "node:path";
import { requireDirectorySync, syncDirectorySync } from "../infra/directory-durability.js";
import {
  readMigrationArtifactIdentity,
  sameMigrationArtifact,
  type MigrationArtifactIdentity,
} from "../infra/session-sqlite-migration-artifact.js";
import {
  canonicalMigrationFilePath,
  hasSymbolicLinkInDirectoryPath,
  listSessionSqliteMigrationManifestPaths,
  readSessionSqliteMigrationManifest,
  resolveSessionSqliteMigrationRunsDir,
  writeSessionSqliteMigrationManifest,
  type SessionSqliteMigrationTargetManifest,
} from "../infra/session-sqlite-migration-manifest.js";
import { getOpenClawDatabaseMaintenanceScope } from "../state/openclaw-state-db-async-lifecycle.js";
import { resolveOpenClawStateSqlitePath } from "../state/openclaw-state-db.paths.js";
import { VERSION } from "../version.js";

/** Record the producer's verified originals in the existing recovery inventory. */
export function recordDoctorMigrationBackups(
  env: NodeJS.ProcessEnv,
  backupId: string,
  inventory: readonly { path: string; identity: fs.BigIntStats; archivePath: string }[],
  versionPhase = false,
  reuse: {
    archiveBackupId?: string;
    originManifestSha256?: string;
    verifiedBackupIdentities?: Map<string, MigrationArtifactIdentity>;
  } = {},
): void {
  const runId = `startup-migration-${backupId}`;
  const archiveBackupId = reuse.archiveBackupId ?? backupId;
  const verification = reuse.originManifestSha256
    ? `cross-build-reuse:startup-migration-${archiveBackupId}:${reuse.originManifestSha256}`
    : undefined;
  if (
    Boolean(reuse.archiveBackupId) !== Boolean(reuse.originManifestSha256) ||
    Boolean(reuse.archiveBackupId) !== Boolean(reuse.verifiedBackupIdentities) ||
    (reuse.archiveBackupId && reuse.archiveBackupId === backupId)
  ) {
    throw new Error("Cross-build recovery manifest inputs are incomplete or ambiguous");
  }
  const assertVerifiedArchive = (
    source: string,
    archivePath: string,
  ): MigrationArtifactIdentity | undefined => {
    const verified = reuse.verifiedBackupIdentities?.get(source);
    if (verification && archivePath !== `${source}.pre-startup-migration-${archiveBackupId}.bak`) {
      throw new Error(`Cross-build backup path differs from the reviewed full group: ${archivePath}`);
    }
    if (verification && !verified) {
      throw new Error(`Cross-build backup identity missing: ${archivePath}`);
    }
    if (verified) {
      const now = fs.lstatSync(archivePath, { bigint: true });
      if (
        !now.isFile() ||
        now.nlink !== 1n ||
        String(now.dev) !== verified.dev ||
        String(now.ino) !== verified.ino ||
        String(now.mtimeNs) !== verified.mtimeNs ||
        Number(now.size) !== verified.size
      ) {
        throw new Error(`Cross-build backup changed after validation: ${archivePath}`);
      }
    }
    return verified;
  };
  const manifestPath = path.join(resolveSessionSqliteMigrationRunsDir(env), `${runId}.json`);
  if (hasSymbolicLinkInDirectoryPath(path.dirname(manifestPath))) {
    throw new Error("Migration backup manifest directory is aliased");
  }
  if (fs.existsSync(manifestPath)) {
    if (verification) {
      for (const { path: source, archivePath } of inventory) {
        assertVerifiedArchive(source, archivePath);
      }
    }
    const existing = readSessionSqliteMigrationManifest(manifestPath);
    if (!existing) {
      throw new Error(`Cannot read migration backup manifest: ${manifestPath}`);
    }
    if (verification) {
      const expectedSources = new Set(inventory.map(({ path: source }) => source));
      if (
        existing.runId !== runId ||
        existing.completedAt ||
        existing.failedAt ||
        existing.targets.length !== inventory.length ||
        new Set(existing.targets.map((target) => target.sqlitePath)).size !==
          expectedSources.size ||
        existing.targets.some((target) => {
          const move = target.completedMoves[0];
          const current = inventory.find(
            ({ path: source }) => source === target.sqlitePath,
          )?.identity;
          return (
            !expectedSources.has(target.sqlitePath) ||
            !current ||
            !move ||
            target.agentId !== "startup-migration" ||
            target.storePath !== target.sqlitePath ||
            target.databaseIdentity?.dev !== String(current.dev) ||
            target.databaseIdentity.ino !== String(current.ino) ||
            target.validationBeforeArchive !== "not_run" ||
            target.issues.length !== 0 ||
            target.completedMoves.length !== 1 ||
            target.plannedMoves.length !== 1 ||
            JSON.stringify(target.plannedMoves[0]) !== JSON.stringify(move) ||
            move.kind !== "database-backup" ||
            move.sourcePath !== target.sqlitePath ||
            move.archivePath !==
              `${target.sqlitePath}.pre-startup-migration-${archiveBackupId}.bak` ||
            move.artifact?.classification !== "repair-original" ||
            move.artifact.disposal.state !== "retained" ||
            move.artifact.dependencies.length !== 0 ||
            move.artifact?.verification !== verification ||
            !reuse.verifiedBackupIdentities?.has(target.sqlitePath) ||
            !sameMigrationArtifact(
              move.artifact.identity,
              reuse.verifiedBackupIdentities.get(target.sqlitePath)!,
            )
          );
        })
      ) {
        throw new Error(`Cross-build recovery manifest changed: ${manifestPath}`);
      }
      // A previous atomic publication may have failed after rename but before
      // its directory sync. Re-establish durability before accepting a retry.
      requireDirectorySync(
        syncDirectorySync(path.dirname(manifestPath)),
        "Cross-build recovery manifest",
      );
    }
    return;
  }
  const targets: SessionSqliteMigrationTargetManifest[] = inventory.map(
    ({ path: source, identity, archivePath }) => {
      const verified = assertVerifiedArchive(source, archivePath);
      const move = {
        kind: "database-backup" as const,
        sourcePath: source,
        archivePath,
        artifact: {
          identity: verified ?? readMigrationArtifactIdentity(archivePath),
          classification: "repair-original" as const,
          reason: verification
            ? "reviewed-cross-build-pre-startup-migration-backup"
            : versionPhase
              ? "pre-version-migration-backup"
              : "pre-startup-migration-backup",
          ...(verification ? { verification } : {}),
          dependencies: [],
          disposal: { state: "retained" as const },
        },
      };
      return {
        agentId: "startup-migration",
        storePath: source,
        sqlitePath: source,
        databaseIdentity: { dev: String(identity.dev), ino: String(identity.ino) },
        plannedMoves: [move],
        completedMoves: [move],
        issues: [],
        validationBeforeArchive: "not_run",
      };
    },
  );
  getOpenClawDatabaseMaintenanceScope()?.assertAdmission();
  writeSessionSqliteMigrationManifest({
    manifestPath,
    manifest: {
      manifestVersion: 3,
      runId,
      openClawVersion: VERSION,
      startedAt: new Date().toISOString(),
      targets,
    },
  });
}

/** Complete a committed version phase, or the full Doctor phase for undeclared migrations. */
export function completeDoctorMigrationBackups(
  env: NodeJS.ProcessEnv,
  verifiedDatabasePaths: readonly string[],
  versionPhaseOnly = false,
): void {
  const maintenance = getOpenClawDatabaseMaintenanceScope();
  if (!maintenance?.ownsSchemaMaintenance) {
    return;
  }
  const verified = new Set(
    [...verifiedDatabasePaths, resolveOpenClawStateSqlitePath(env)].map(canonicalMigrationFilePath),
  );
  const manifests = listSessionSqliteMigrationManifestPaths(env).map((manifestPath) => ({
    manifestPath,
    manifest: readSessionSqliteMigrationManifest(manifestPath),
  }));
  // A new candidate owns its completion receipt. The originating failed run's
  // manifest remains byte-for-byte historical, even after the new run succeeds.
  const borrowedOriginRuns = new Set(
    manifests.flatMap(
      ({ manifest }) =>
        manifest?.targets.flatMap((target) =>
          target.completedMoves.flatMap((move) => {
            const marker =
              /^cross-build-reuse:(startup-migration-[a-f0-9-]{36}):[a-f0-9]{64}$/u.exec(
                move.artifact?.verification ?? "",
              );
            return marker ? [marker[1]] : [];
          }),
        ) ?? [],
    ),
  );
  for (const { manifestPath, manifest } of manifests) {
    if (
      !manifest ||
      borrowedOriginRuns.has(manifest.runId) ||
      manifest.completedAt ||
      !manifest.targets.length ||
      (versionPhaseOnly &&
        !manifest.targets.every((target) =>
          target.completedMoves.every(
            (move) => move.artifact?.reason === "pre-version-migration-backup",
          ),
        )) ||
      !manifest.targets.every(({ databaseIdentity, sqlitePath }) => {
        if (!databaseIdentity || !verified.has(sqlitePath)) {
          return false;
        }
        const current = fs.lstatSync(sqlitePath, { bigint: true, throwIfNoEntry: false });
        return (
          current?.isFile() &&
          current.nlink === 1n &&
          String(current.dev) === databaseIdentity.dev &&
          String(current.ino) === databaseIdentity.ino
        );
      })
    ) {
      continue;
    }
    maintenance.assertAdmission();
    for (const target of manifest.targets) {
      target.validationBeforeArchive = "passed";
    }
    manifest.completedAt = new Date().toISOString();
    writeSessionSqliteMigrationManifest({ manifest, manifestPath });
  }
}
