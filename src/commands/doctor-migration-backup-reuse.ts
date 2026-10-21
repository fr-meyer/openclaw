import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import {
  readMigrationArtifactIdentity,
  sameMigrationArtifact,
} from "../infra/session-sqlite-migration-artifact.js";
import {
  hasSymbolicLinkInDirectoryPath,
  readSessionSqliteMigrationManifest,
  resolveSessionSqliteMigrationRunsDir,
} from "../infra/session-sqlite-migration-manifest.js";
import { DoctorMaintenanceRefusalError } from "../infra/update-doctor-result.js";
import { resolveRuntimeServiceCommit, VERSION } from "../version.js";

export const DOCTOR_BACKUP_REUSE_ENV = "OPENCLAW_DOCTOR_BACKUP_REUSE_PROOF";

// Each origin is a reviewed source and immutable image pair. A later candidate
// must carry its own reviewed source change to extend this compatibility list.
const REVIEWED_ORIGINS = [
  {
    sourceSha: "ae85778296da373dfe7d80101931bafac1acc9dd",
    imageDigest: "sha256:f41c7a7762f7a051636b899dac54110c482fb91352431ba6957343b9828f2e9c",
    imageReceiptSha256: "98ba31371e306b4e8878161ebf2dce0d021f1be2a3ae5e10384e238fdc9e6178",
  },
] as const;

const SHA = /^[a-f0-9]{64}$/u;
const COMMIT = /^[a-f0-9]{40}$/u;
const BACKUP_ID = /^[a-f0-9]{8}-[a-f0-9]{4}-8[a-f0-9]{3}-8[a-f0-9]{3}-[a-f0-9]{12}$/u;

export type ReviewedDoctorBackupReuse = {
  schema: "openclaw.doctor-backup-reuse.v1";
  originSourceSha: string;
  originImageDigest: string;
  originImageReceiptSha256: string;
  targetSourceSha: string;
  backupId: string;
  manifestSha256: string;
};

function refuse(reason: string): never {
  throw new DoctorMaintenanceRefusalError(
    `Cannot reuse the earlier pre-migration SQLite backup group: ${reason}. Original files and receipts were preserved.`,
    { kind: "data-at-risk", reason: "incomplete-migration" },
  );
}

export function parseReviewedDoctorBackupReuse(
  env: NodeJS.ProcessEnv,
): ReviewedDoctorBackupReuse | undefined {
  const raw = env[DOCTOR_BACKUP_REUSE_ENV];
  if (raw === undefined) {
    return undefined;
  }
  if (raw.length > 2048) {
    refuse("proof exceeds the bounded input size");
  }
  let proof: unknown;
  try {
    proof = JSON.parse(raw);
  } catch {
    refuse("proof is not JSON");
  }
  if (!proof || typeof proof !== "object" || Array.isArray(proof)) {
    refuse("proof is not an object");
  }
  const candidate = proof as Record<string, unknown>;
  const keys = [
    "schema",
    "originSourceSha",
    "originImageDigest",
    "originImageReceiptSha256",
    "targetSourceSha",
    "backupId",
    "manifestSha256",
  ];
  if (
    Object.keys(candidate).toSorted().join(",") !== keys.toSorted().join(",") ||
    candidate.schema !== "openclaw.doctor-backup-reuse.v1" ||
    typeof candidate.originSourceSha !== "string" ||
    !COMMIT.test(candidate.originSourceSha) ||
    typeof candidate.originImageDigest !== "string" ||
    !/^sha256:[a-f0-9]{64}$/u.test(candidate.originImageDigest) ||
    typeof candidate.originImageReceiptSha256 !== "string" ||
    !SHA.test(candidate.originImageReceiptSha256) ||
    typeof candidate.targetSourceSha !== "string" ||
    !COMMIT.test(candidate.targetSourceSha) ||
    typeof candidate.backupId !== "string" ||
    !BACKUP_ID.test(candidate.backupId) ||
    typeof candidate.manifestSha256 !== "string" ||
    !SHA.test(candidate.manifestSha256)
  ) {
    refuse("proof fields or syntax differ from the reviewed contract");
  }
  if (
    VERSION !== "2026.10.5" ||
    resolveRuntimeServiceCommit() !== candidate.targetSourceSha ||
    candidate.targetSourceSha === candidate.originSourceSha ||
    !REVIEWED_ORIGINS.some(
      (origin) =>
        origin.sourceSha === candidate.originSourceSha &&
        origin.imageDigest === candidate.originImageDigest &&
        origin.imageReceiptSha256 === candidate.originImageReceiptSha256,
    )
  ) {
    refuse("the running build and reviewed origin image do not match");
  }
  return candidate as ReviewedDoctorBackupReuse;
}

export function verifyReviewedDoctorBackupReuse(params: {
  env: NodeJS.ProcessEnv;
  proof: ReviewedDoctorBackupReuse;
  inventory: readonly { path: string; identity: fs.BigIntStats }[];
  assertCurrent: () => void;
}): Map<string, ReturnType<typeof readMigrationArtifactIdentity>> {
  const { proof, inventory, assertCurrent } = params;
  const manifestPath = path.join(
    resolveSessionSqliteMigrationRunsDir(params.env),
    `startup-migration-${proof.backupId}.json`,
  );
  if (hasSymbolicLinkInDirectoryPath(path.dirname(manifestPath))) {
    refuse("recovery manifest directory is aliased");
  }
  const before = fs.lstatSync(manifestPath, { bigint: true, throwIfNoEntry: false });
  if (
    !before?.isFile() ||
    before.nlink !== 1n ||
    before.size > 1024n * 1024n ||
    before.uid !== BigInt(process.getuid?.() ?? -1) ||
    (before.mode & 0o077n) !== 0n
  ) {
    refuse("origin recovery manifest is missing, aliased, or oversized");
  }
  assertCurrent();
  const raw = fs.readFileSync(manifestPath);
  if (createHash("sha256").update(raw).digest("hex") !== proof.manifestSha256) {
    refuse("origin recovery manifest bytes changed");
  }
  const manifest = readSessionSqliteMigrationManifest(manifestPath);
  const after = fs.lstatSync(manifestPath, { bigint: true });
  if (
    before.dev !== after.dev ||
    before.ino !== after.ino ||
    before.size !== after.size ||
    before.mtimeNs !== after.mtimeNs ||
    before.ctimeNs !== after.ctimeNs ||
    !manifest ||
    manifest.manifestVersion !== 3 ||
    manifest.runId !== `startup-migration-${proof.backupId}` ||
    manifest.openClawVersion !== VERSION ||
    manifest.completedAt ||
    manifest.failedAt ||
    manifest.restore ||
    manifest.failureReports ||
    manifest.targets.length !== inventory.length
  ) {
    refuse("origin recovery manifest is unstable or incomplete");
  }
  const targets = new Map(manifest.targets.map((target) => [target.sqlitePath, target]));
  if (targets.size !== inventory.length) {
    refuse("origin backup inventory has duplicate or missing database paths");
  }
  const verified = new Map<string, ReturnType<typeof readMigrationArtifactIdentity>>();
  for (const { path: source, identity } of inventory) {
    assertCurrent();
    const target = targets.get(source);
    const archivePath = `${source}.pre-startup-migration-${proof.backupId}.bak`;
    const move = target?.completedMoves[0];
    if (
      !target ||
      identity.nlink !== 1n ||
      target.agentId !== "startup-migration" ||
      target.databaseIdentity?.dev !== String(identity.dev) ||
      target.databaseIdentity.ino !== String(identity.ino) ||
      target.storePath !== source ||
      target.validationBeforeArchive !== "not_run" ||
      target.issues.length !== 0 ||
      target.plannedMoves.length !== 1 ||
      target.completedMoves.length !== 1 ||
      target.plannedMoves[0]?.archivePath !== archivePath ||
      JSON.stringify(target.plannedMoves[0]) !== JSON.stringify(move) ||
      move?.kind !== "database-backup" ||
      move.sourcePath !== source ||
      move.archivePath !== archivePath ||
      move.artifact?.classification !== "repair-original" ||
      move.artifact.disposal.state !== "retained" ||
      move.artifact.dependencies.length !== 0
    ) {
      refuse("origin backup group does not match the current physical database inventory");
    }
    let current: ReturnType<typeof readMigrationArtifactIdentity>;
    try {
      current = readMigrationArtifactIdentity(archivePath);
    } catch {
      refuse("an origin backup is missing, aliased, or changed while hashing");
    }
    if (!sameMigrationArtifact(current, move.artifact.identity)) {
      refuse("an origin backup differs from its recorded content identity");
    }
    verified.set(source, current);
  }
  assertCurrent();
  const final = fs.lstatSync(manifestPath, { bigint: true });
  if (
    before.dev !== final.dev ||
    before.ino !== final.ino ||
    before.size !== final.size ||
    before.mtimeNs !== final.mtimeNs ||
    before.ctimeNs !== final.ctimeNs ||
    createHash("sha256").update(fs.readFileSync(manifestPath)).digest("hex") !==
      proof.manifestSha256
  ) {
    refuse("origin recovery manifest changed during backup validation");
  }
  return verified;
}
