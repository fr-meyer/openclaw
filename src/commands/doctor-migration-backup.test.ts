import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as sqliteVec from "../../packages/memory-host-sdk/src/host/sqlite-vec.js";
import { useAutoCleanupTempDirTracker } from "../../test/helpers/temp-dir.js";
import * as directoryDurability from "../infra/directory-durability.js";
import { readMigrationArtifactIdentity } from "../infra/session-sqlite-migration-artifact.js";
import * as sqliteSnapshot from "../infra/sqlite-snapshot.js";
import { createOpenClawDatabaseMaintenanceScope } from "../state/openclaw-state-db-async-lifecycle.js";
import * as version from "../version.js";
import {
  completeDoctorMigrationBackups,
  recordDoctorMigrationBackups,
} from "./doctor-migration-backup-artifacts.js";
import { DOCTOR_BACKUP_REUSE_ENV } from "./doctor-migration-backup-reuse.js";
import {
  backupDoctorMigrationDatabases,
  backupDoctorSqliteDatabases,
} from "./doctor-migration-backup.js";
import { inspectSessionSqliteRecovery } from "./doctor-session-sqlite-recovery-inventory.js";

const tempDirs = useAutoCleanupTempDirTracker(afterEach);

// The retained cross-build contract is qualified only for the original 10.5
// transition. Test that contract explicitly without admitting this new release.
const releaseFixture = vi.hoisted(() => ({ version: "2026.10.5" }));
vi.mock("../version.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../version.js")>();
  return {
    ...actual,
    get VERSION() {
      return releaseFixture.version;
    },
  };
});
beforeEach(() => {
  releaseFixture.version = "2026.10.5";
});

function seedDatabase(databasePath: string, value: string) {
  fs.mkdirSync(path.dirname(databasePath), { recursive: true });
  const database = new DatabaseSync(databasePath);
  try {
    database.exec("PRAGMA user_version = 1; CREATE TABLE preserved (value TEXT NOT NULL);");
    database.prepare("INSERT INTO preserved VALUES (?)").run(value);
  } finally {
    database.close();
  }
}

function readPreservedValue(databasePath: string) {
  const database = new DatabaseSync(databasePath, { readOnly: true });
  try {
    return database.prepare("SELECT value FROM preserved").get()?.value;
  } finally {
    database.close();
  }
}

function listBackups(databasePath: string) {
  return fs
    .readdirSync(path.dirname(databasePath))
    .filter(
      (name) =>
        name.startsWith(`${path.basename(databasePath)}.pre-startup-migration-`) &&
        name.endsWith(".bak"),
    )
    .map((name) => path.join(path.dirname(databasePath), name));
}

function createFixture() {
  const stateDir = tempDirs.make("openclaw-doctor-backup-");
  const shared = path.join(stateDir, "state", "openclaw.sqlite");
  const agent = path.join(stateDir, "agents", "main", "openclaw-agent.sqlite");
  seedDatabase(shared, "shared before migration");
  seedDatabase(agent, "agent before migration");
  const env: NodeJS.ProcessEnv & { OPENCLAW_STATE_DIR: string } = {
    ...process.env,
    OPENCLAW_STATE_DIR: stateDir,
  };
  return { shared, agent, env };
}

function prepareCrossBuildGroup(fixture: ReturnType<typeof createFixture>) {
  const original = [fixture.shared, fixture.agent].map((source) => listBackups(source)[0]!);
  const group = /\.pre-startup-migration-([a-f0-9-]{36})\.bak$/u.exec(original[0]!)?.[1];
  if (!group) {
    throw new Error("synthetic old group missing");
  }
  const manifest = path.join(
    fixture.env.OPENCLAW_STATE_DIR,
    "session-sqlite-migration-runs",
    `startup-migration-${group}.json`,
  );
  const originalManifest = fs.readFileSync(manifest);
  const targetSourceSha = "b".repeat(40);
  const proof = {
    schema: "openclaw.doctor-backup-reuse.v1",
    originSourceSha: "ae85778296da373dfe7d80101931bafac1acc9dd",
    originImageDigest: "sha256:f41c7a7762f7a051636b899dac54110c482fb91352431ba6957343b9828f2e9c",
    originImageReceiptSha256: "98ba31371e306b4e8878161ebf2dce0d021f1be2a3ae5e10384e238fdc9e6178",
    targetSourceSha,
    backupId: group,
    manifestSha256: createHash("sha256").update(originalManifest).digest("hex"),
  };
  fixture.env[DOCTOR_BACKUP_REUSE_ENV] = JSON.stringify(proof);
  return { original, group, manifest, originalManifest, proof, targetSourceSha };
}

async function backup(
  fixture: ReturnType<typeof createFixture>,
  pendingDatabasePaths = [fixture.agent],
  databasePaths = [fixture.agent],
) {
  const maintenance = createOpenClawDatabaseMaintenanceScope({
    schemaMaintenance: true,
    assertOwnerCurrent: () => {},
  });
  try {
    return await maintenance.run(() =>
      backupDoctorMigrationDatabases({ env: fixture.env, pendingDatabasePaths, databasePaths }),
    );
  } finally {
    await maintenance.close();
  }
}

describe("Doctor migration backup retries", () => {
  it("retains required recovery snapshots despite already verified source identities", async () => {
    releaseFixture.version = "2026.10.6";
    const fixture = createFixture();
    const maintenance = createOpenClawDatabaseMaintenanceScope({
      schemaMaintenance: true,
      assertOwnerCurrent: () => {},
    });
    try {
      const result = await maintenance.run(() =>
        backupDoctorSqliteDatabases({
          env: fixture.env,
          pendingDatabasePaths: [fixture.agent],
          databasePaths: [fixture.agent],
          authority: { assertCurrent: () => maintenance.assertAdmission() },
          requireSnapshots: true,
          verifiedSnapshots: [fixture.shared, fixture.agent].map((sourcePath) => {
            const { dev, ino } = fs.statSync(sourcePath);
            return {
              sourcePath,
              dev,
              ino,
              ...(sourcePath === fixture.shared
                ? { role: "global" as const }
                : { role: "agent" as const, agentId: "main" }),
            };
          }),
        }),
      );
      expect(result.snapshots).toHaveLength(2);
      expect(readPreservedValue(listBackups(fixture.agent)[0]!)).toBe("agent before migration");
      expect(readPreservedValue(listBackups(fixture.shared)[0]!)).toBe("shared before migration");
    } finally {
      await maintenance.close();
    }
  });

  it("refuses the earlier cross-build proof on the unqualified 10.6 release", async () => {
    const fixture = createFixture();
    await backup(fixture);
    const old = prepareCrossBuildGroup(fixture);
    const commit = vi
      .spyOn(version, "resolveRuntimeServiceFullCommit")
      .mockReturnValue(old.targetSourceSha);
    releaseFixture.version = "2026.10.6";
    try {
      await expect(backup(fixture)).rejects.toThrow(
        "the running build and reviewed origin image do not match",
      );
      expect([fixture.shared, fixture.agent].flatMap(listBackups)).toEqual(old.original);
      expect(fs.readFileSync(old.manifest)).toEqual(old.originalManifest);
    } finally {
      commit.mockRestore();
    }
  });

  it("does not use a migration reuse proof to authorize required same-schema recovery", async () => {
    const fixture = createFixture();
    await backup(fixture);
    const old = prepareCrossBuildGroup(fixture);
    const commit = vi
      .spyOn(version, "resolveRuntimeServiceFullCommit")
      .mockReturnValue(old.targetSourceSha);
    try {
      await expect(
        backupDoctorSqliteDatabases({
          env: fixture.env,
          pendingDatabasePaths: [fixture.agent],
          databasePaths: [fixture.agent],
          authority: { assertCurrent: () => {} },
          requireSnapshots: true,
          repair: { key: "published-missing-agent-deletion-journal", validate: () => {} },
        }),
      ).rejects.toThrow("Cross-build migration backup reuse cannot authorize a same-schema repair");
      expect([fixture.shared, fixture.agent].flatMap(listBackups)).toEqual(old.original);
      expect(fs.readFileSync(old.manifest)).toEqual(old.originalManifest);
    } finally {
      commit.mockRestore();
    }
  });

  it("rejects a different loaded full commit even when its seven-character prefix matches", async () => {
    const fixture = createFixture();
    await backup(fixture);
    const old = prepareCrossBuildGroup(fixture);
    const other = `${old.targetSourceSha.slice(0, 7)}${"c".repeat(33)}`;
    const commit = vi.spyOn(version, "resolveRuntimeServiceFullCommit").mockReturnValue(other);
    try {
      await expect(backup(fixture)).rejects.toMatchObject({
        refusal: { kind: "data-at-risk", reason: "incomplete-migration" },
      });
      expect([fixture.shared, fixture.agent].flatMap(listBackups)).toEqual(old.original);
      expect(fs.readFileSync(old.manifest)).toEqual(old.originalManifest);
    } finally {
      commit.mockRestore();
    }
  });

  it("reuses a reviewed earlier-build group and completes only the successor manifest", async () => {
    const fixture = createFixture();
    await backup(fixture);
    const old = prepareCrossBuildGroup(fixture);
    const commit = vi
      .spyOn(version, "resolveRuntimeServiceFullCommit")
      .mockReturnValue(old.targetSourceSha);
    const build = vi
      .spyOn(version, "resolveRuntimeServiceBuildId")
      .mockReturnValue("successor-build");
    try {
      const agent = new DatabaseSync(fixture.agent);
      try {
        agent.exec("UPDATE preserved SET value = 'partly migrated';");
      } finally {
        agent.close();
      }
      await backup(fixture);
      await backup(fixture);
      expect([fixture.shared, fixture.agent].map((source) => listBackups(source)[0])).toEqual(
        old.original,
      );
      expect([fixture.shared, fixture.agent].flatMap(listBackups)).toHaveLength(2);
      expect(readPreservedValue(old.original[1]!)).toBe("agent before migration");
      const successor = fs
        .readdirSync(path.dirname(old.manifest))
        .filter((name) => name.startsWith("startup-migration-") && !name.includes(old.group));
      expect(successor).toHaveLength(1);
      const successorPath = path.join(path.dirname(old.manifest), successor[0]!);
      const recorded = JSON.parse(fs.readFileSync(successorPath, "utf8"));
      expect(
        recorded.targets
          .map(
            (target: { completedMoves: Array<{ archivePath: string }> }) =>
              target.completedMoves[0]?.archivePath,
          )
          .toSorted(),
      ).toEqual(old.original.toSorted());
      expect(recorded.targets[0]?.completedMoves[0]?.artifact?.verification).toContain(
        `cross-build-reuse:startup-migration-${old.group}:`,
      );
      const maintenance = createOpenClawDatabaseMaintenanceScope({
        schemaMaintenance: true,
        assertOwnerCurrent: () => {},
      });
      try {
        await maintenance.run(() =>
          completeDoctorMigrationBackups(fixture.env, [fixture.shared, fixture.agent]),
        );
      } finally {
        await maintenance.close();
      }
      expect(fs.readFileSync(old.manifest)).toEqual(old.originalManifest);
      expect(JSON.parse(fs.readFileSync(successorPath, "utf8")).completedAt).toBeTruthy();
    } finally {
      commit.mockRestore();
      build.mockRestore();
    }
  });

  it.each(["manifest", "missing", "aliased", "changed", "source", "capture"] as const)(
    "refuses cross-build reuse when the %s proof or artifact changes without recapture",
    async (damage) => {
      const fixture = createFixture();
      await backup(fixture);
      const old = prepareCrossBuildGroup(fixture);
      const commit = vi
        .spyOn(version, "resolveRuntimeServiceFullCommit")
        .mockReturnValue(old.targetSourceSha);
      const build = vi
        .spyOn(version, "resolveRuntimeServiceBuildId")
        .mockReturnValue("successor-build");
      try {
        if (damage === "manifest") {
          old.proof.manifestSha256 = "0".repeat(64);
          fixture.env[DOCTOR_BACKUP_REUSE_ENV] = JSON.stringify(old.proof);
        } else if (damage === "missing") {
          fs.unlinkSync(old.original[1]!);
        } else if (damage === "aliased") {
          fs.linkSync(old.original[1]!, `${old.original[1]!}.alias`);
        } else if (damage === "changed") {
          const database = new DatabaseSync(old.original[1]!);
          try {
            database.exec("UPDATE preserved SET value = 'changed original';");
          } finally {
            database.close();
          }
        } else if (damage === "source") {
          const replacement = `${fixture.agent}.replacement`;
          seedDatabase(replacement, "different source");
          fs.renameSync(replacement, fixture.agent);
        } else if (damage === "capture") {
          fs.writeFileSync(`${old.original[0]}.capturing`, "");
        }
        await expect(backup(fixture)).rejects.toMatchObject({
          refusal: { kind: "data-at-risk", reason: "incomplete-migration" },
        });
        expect(fs.readFileSync(old.manifest)).toEqual(old.originalManifest);
        const currentBackups = [fixture.shared, fixture.agent].flatMap(listBackups);
        expect(currentBackups).toEqual(damage === "missing" ? [old.original[0]] : old.original);
      } finally {
        commit.mockRestore();
        build.mockRestore();
      }
    },
  );
  it.each(["completed", "source-identity"] as const)(
    "refuses a %s successor receipt while preserving the origin group",
    async (damage) => {
      const fixture = createFixture();
      await backup(fixture);
      const old = prepareCrossBuildGroup(fixture);
      const commit = vi
        .spyOn(version, "resolveRuntimeServiceFullCommit")
        .mockReturnValue(old.targetSourceSha);
      const build = vi
        .spyOn(version, "resolveRuntimeServiceBuildId")
        .mockReturnValue("successor-build");
      try {
        await backup(fixture);
        const successorName = fs
          .readdirSync(path.dirname(old.manifest))
          .find((name) => name.startsWith("startup-migration-") && !name.includes(old.group));
        expect(successorName).toBeTruthy();
        const successorPath = path.join(path.dirname(old.manifest), successorName!);
        const successor = JSON.parse(fs.readFileSync(successorPath, "utf8"));
        if (damage === "completed") {
          successor.completedAt = new Date().toISOString();
        } else {
          successor.targets[0].databaseIdentity.ino = "0";
        }
        fs.writeFileSync(successorPath, JSON.stringify(successor));
        await expect(backup(fixture)).rejects.toMatchObject({
          refusal: { kind: "data-at-risk", reason: "incomplete-migration" },
        });
        expect(fs.readFileSync(old.manifest)).toEqual(old.originalManifest);
        expect([fixture.shared, fixture.agent].flatMap(listBackups)).toEqual(old.original);
      } finally {
        commit.mockRestore();
        build.mockRestore();
      }
    },
  );
  it("requires a durable successor receipt on retry after publication sync failure", async () => {
    const fixture = createFixture();
    await backup(fixture);
    const old = prepareCrossBuildGroup(fixture);
    const commit = vi
      .spyOn(version, "resolveRuntimeServiceFullCommit")
      .mockReturnValue(old.targetSourceSha);
    const build = vi
      .spyOn(version, "resolveRuntimeServiceBuildId")
      .mockReturnValue("successor-build");
    const actualSync = directoryDurability.syncDirectorySync;
    const manifestDirectory = path.dirname(old.manifest);
    let failedSyncs = 0;
    const sync = vi
      .spyOn(directoryDurability, "syncDirectorySync")
      .mockImplementation((directory) => {
        if (directory === manifestDirectory && failedSyncs++ < 2) {
          throw new Error("synthetic successor directory sync failure");
        }
        return actualSync(directory);
      });
    try {
      await expect(backup(fixture)).rejects.toMatchObject({
        refusal: { kind: "data-at-risk", reason: "incomplete-migration" },
      });
      const successor = fs
        .readdirSync(manifestDirectory)
        .filter((name) => name.startsWith("startup-migration-") && !name.includes(old.group));
      expect(successor).toHaveLength(1);
      await expect(backup(fixture)).rejects.toMatchObject({
        refusal: { kind: "data-at-risk", reason: "incomplete-migration" },
      });
      expect(failedSyncs).toBe(2);
      await backup(fixture);
      expect(failedSyncs).toBe(3);
      expect(fs.readFileSync(old.manifest)).toEqual(old.originalManifest);
      expect([fixture.shared, fixture.agent].flatMap(listBackups)).toEqual(old.original);
    } finally {
      sync.mockRestore();
      commit.mockRestore();
      build.mockRestore();
    }
  });

  it("refuses a replaced backup while resuming an existing successor receipt", async () => {
    const fixture = createFixture();
    await backup(fixture);
    const old = prepareCrossBuildGroup(fixture);
    const commit = vi
      .spyOn(version, "resolveRuntimeServiceFullCommit")
      .mockReturnValue(old.targetSourceSha);
    const build = vi
      .spyOn(version, "resolveRuntimeServiceBuildId")
      .mockReturnValue("successor-build");
    try {
      await backup(fixture);
      const successorName = fs
        .readdirSync(path.dirname(old.manifest))
        .find((name) => name.startsWith("startup-migration-") && !name.includes(old.group));
      expect(successorName).toBeTruthy();
      const successorId = /startup-migration-([a-f0-9-]{36})\.json$/u.exec(successorName!)?.[1];
      expect(successorId).toBeTruthy();
      const inventory = [fixture.shared, fixture.agent].map((source) => ({
        path: source,
        identity: fs.statSync(source, { bigint: true }),
      }));
      const verifiedBackupIdentities = new Map(
        inventory.map(({ path: source }) => [
          source,
          readMigrationArtifactIdentity(`${source}.pre-startup-migration-${old.group}.bak`),
        ]),
      );
      fs.renameSync(old.original[1]!, `${old.original[1]!}.retained`);
      fs.copyFileSync(`${old.original[1]!}.retained`, old.original[1]!);
      expect(() =>
        recordDoctorMigrationBackups(fixture.env, successorId!, inventory, {
          archiveBackupId: old.group,
          originManifestSha256: old.proof.manifestSha256,
          verifiedBackupIdentities,
        }),
      ).toThrow("Cross-build backup changed after validation");
      expect(fs.readFileSync(old.manifest)).toEqual(old.originalManifest);
    } finally {
      commit.mockRestore();
      build.mockRestore();
    }
  });
  it("backs up the full inventory when only the shared database has a pending migration", async () => {
    const fixture = createFixture();
    await backup(fixture, [fixture.shared]);
    expect(listBackups(fixture.shared)).toHaveLength(1);
    expect(listBackups(fixture.agent)).toHaveLength(1);
    expect(readPreservedValue(listBackups(fixture.agent)[0]!)).toBe("agent before migration");
    const preview = inspectSessionSqliteRecovery({ cfg: {}, env: fixture.env });
    expect(preview.artifacts).toHaveLength(2);
    expect(preview.artifacts).toEqual(
      expect.arrayContaining(
        [fixture.shared, fixture.agent].map((database) =>
          expect.objectContaining({
            path: listBackups(database)[0],
            outcome: "protected",
            reason: "incomplete-recovery-operation",
          }),
        ),
      ),
    );
  });

  it("does not reuse a completed group until capture-marker removal is durable", async () => {
    const fixture = createFixture();
    const syncDirectory = directoryDurability.syncDirectorySync;
    const sync = vi
      .spyOn(directoryDurability, "syncDirectorySync")
      .mockImplementationOnce(syncDirectory)
      .mockImplementationOnce(() => {
        throw new Error("capture completion sync failed");
      })
      .mockImplementationOnce(() => {
        throw new Error("capture completion sync failed");
      });
    try {
      await expect(backup(fixture)).rejects.toThrow("capture completion sync failed");
      await expect(backup(fixture)).rejects.toThrow("capture completion sync failed");
    } finally {
      sync.mockRestore();
    }
    const originals = [fixture.agent, fixture.shared].flatMap(listBackups);
    await backup(fixture);
    expect([fixture.agent, fixture.shared].flatMap(listBackups)).toEqual(originals);
  });

  it("recaptures the entire incomplete group after interruption and intervening writes", async () => {
    const fixture = createFixture();
    const originalCreateSnapshot = sqliteSnapshot.createVerifiedSqliteSnapshot;
    const createSnapshot = vi
      .spyOn(sqliteSnapshot, "createVerifiedSqliteSnapshot")
      .mockImplementationOnce(originalCreateSnapshot)
      .mockRejectedValueOnce(new Error("interrupted backup"));
    try {
      await expect(backup(fixture)).rejects.toThrow("interrupted backup");
    } finally {
      createSnapshot.mockRestore();
    }
    expect(listBackups(fixture.agent)).toHaveLength(1);
    expect(listBackups(fixture.shared)).toHaveLength(0);
    for (const source of [fixture.agent, fixture.shared]) {
      const database = new DatabaseSync(source);
      try {
        database.exec("UPDATE preserved SET value = 'after interruption';");
      } finally {
        database.close();
      }
    }
    await backup(fixture);
    for (const source of [fixture.agent, fixture.shared]) {
      const backups = listBackups(source);
      expect(backups).toHaveLength(1);
      expect(readPreservedValue(backups[0]!)).toBe("after interruption");
    }
  });

  it("reuses the original rollback group after partial migration and repeated retries", async () => {
    const fixture = createFixture();
    const secondAgent = path.join(path.dirname(fixture.agent), "second.sqlite");
    seedDatabase(secondAgent, "second before migration");
    const inventory = [fixture.agent, secondAgent];
    await backup(fixture, inventory, inventory);
    const originals = [fixture.shared, ...inventory].map((source) => listBackups(source)[0]!);
    expect(new Set(originals.map((name) => name.split(".pre-startup-migration-")[1])).size).toBe(1);

    const migrated = new DatabaseSync(fixture.agent);
    try {
      migrated.exec("PRAGMA user_version = 24; UPDATE preserved SET value = 'partially migrated';");
    } finally {
      migrated.close();
    }
    const load = vi
      .spyOn(sqliteVec, "loadSqliteVecExtension")
      .mockRejectedValue(new Error("sqlite-vec cannot load on this CPU"));
    try {
      for (let attempt = 0; attempt < 4; attempt++) {
        await backup(fixture, [secondAgent], inventory.toReversed());
      }
      expect(load).not.toHaveBeenCalled();
    } finally {
      load.mockRestore();
    }

    expect([fixture.shared, ...inventory].flatMap(listBackups).toSorted()).toEqual(
      originals.toSorted(),
    );
    expect(readPreservedValue(listBackups(fixture.agent)[0]!)).toBe("agent before migration");
    expect(readPreservedValue(listBackups(fixture.shared)[0]!)).toBe("shared before migration");
    expect(readPreservedValue(fixture.agent)).toBe("partially migrated");
  });

  it.each(["missing-agent", "corrupt-agent", "symlink-agent", "missing-shared"] as const)(
    "preserves a completed rollback group when %s damage is discovered after partial migration",
    async (damage) => {
      const fixture = createFixture();
      const secondAgent = path.join(path.dirname(fixture.agent), "second.sqlite");
      seedDatabase(secondAgent, "second before migration");
      const inventory = [fixture.agent, secondAgent];
      await backup(fixture, inventory, inventory);
      const originalAgent = listBackups(fixture.agent)[0]!;
      const originalShared = listBackups(fixture.shared)[0]!;
      const originalSecond = listBackups(secondAgent)[0]!;
      const originalBytes = fs.readFileSync(originalSecond);
      const migrated = new DatabaseSync(fixture.agent);
      try {
        migrated.exec(
          "PRAGMA user_version = 24; UPDATE preserved SET value = 'partially migrated';",
        );
      } finally {
        migrated.close();
      }
      const damaged = damage === "missing-shared" ? originalShared : originalAgent;
      if (damage === "corrupt-agent") {
        fs.writeFileSync(damaged, "not a SQLite snapshot");
      } else {
        fs.unlinkSync(damaged);
        if (damage === "symlink-agent") {
          fs.symlinkSync(fixture.agent, damaged);
        }
      }
      const remaining = [fixture.shared, ...inventory].flatMap(listBackups);

      await expect(backup(fixture, [secondAgent], inventory)).rejects.toMatchObject({
        refusal: { kind: "data-at-risk", reason: "incomplete-migration" },
      });
      expect([fixture.shared, ...inventory].flatMap(listBackups)).toEqual(remaining);
      expect(fs.readFileSync(originalSecond)).toEqual(originalBytes);
      expect(readPreservedValue(fixture.agent)).toBe("partially migrated");
      if (damage === "missing-shared") {
        expect(readPreservedValue(originalAgent)).toBe("agent before migration");
      }
    },
  );

  it.each(["added", "replaced"] as const)(
    "starts a new coherent group for a database that was %s without removing older backups",
    async (change) => {
      const fixture = createFixture();
      await backup(fixture);
      const originalSharedBackup = listBackups(fixture.shared)[0]!;
      const legacyBackup = `${fixture.shared}.pre-startup-migration-legacy-operator-copy.bak`;
      fs.copyFileSync(originalSharedBackup, legacyBackup);
      const originalBytes = fs.readFileSync(legacyBackup);
      const newAgent = path.join(path.dirname(fixture.agent), "replacement.sqlite");
      seedDatabase(newAgent, "new agent history");
      if (change === "replaced") {
        fs.renameSync(newAgent, fixture.agent);
      }
      const currentAgent = change === "replaced" ? fixture.agent : newAgent;
      const inventory = change === "replaced" ? [fixture.agent] : [fixture.agent, newAgent];
      await backup(fixture, [currentAgent], inventory);
      await backup(fixture, [currentAgent], inventory);

      const newSharedBackups = listBackups(fixture.shared).filter(
        (pathname) => pathname !== originalSharedBackup && pathname !== legacyBackup,
      );
      expect(newSharedBackups).toHaveLength(1);
      const newId = newSharedBackups[0]!.split(".pre-startup-migration-")[1];
      const currentBackup = listBackups(currentAgent).find((pathname) => pathname.endsWith(newId!));
      expect(currentBackup).toBeDefined();
      expect(readPreservedValue(currentBackup!)).toBe("new agent history");
      expect(fs.readFileSync(legacyBackup)).toEqual(originalBytes);
      expect(fs.existsSync(originalSharedBackup)).toBe(true);
    },
  );

  it("captures current state for a new candidate build with unchanged database identities and schemas", async () => {
    const fixture = createFixture();
    await backup(fixture);
    const sources = [fixture.agent, fixture.shared];
    const originalBackups = sources.map((source) => listBackups(source)[0]!);
    const originalBytes = originalBackups.map((snapshot) => fs.readFileSync(snapshot));
    for (const source of sources) {
      const database = new DatabaseSync(source);
      try {
        database.exec("UPDATE preserved SET value = 'next build history';");
      } finally {
        database.close();
      }
    }
    const build = vi
      .spyOn(version, "resolveRuntimeServiceBuildId")
      .mockReturnValue("migration-backup-next-build");
    try {
      await backup(fixture);
      await backup(fixture);
    } finally {
      build.mockRestore();
    }

    const newBackups = sources.flatMap((source) => {
      const backups = listBackups(source);
      expect(backups).toHaveLength(2);
      return backups.filter((snapshot) => !originalBackups.includes(snapshot));
    });
    expect(new Set(newBackups.map((name) => name.split(".pre-startup-migration-")[1])).size).toBe(
      1,
    );
    expect(newBackups.map(readPreservedValue)).toEqual([
      "next build history",
      "next build history",
    ]);
    expect(originalBackups.map((snapshot) => fs.readFileSync(snapshot))).toEqual(originalBytes);
  });
});
