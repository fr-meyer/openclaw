// Config publication stages candidates before consuming recovery history.
import type fs from "node:fs";
import path from "node:path";
import { tempFile } from "@openclaw/fs-safe/advanced";
import { replaceFileAtomicSync, type ReplaceFileAtomicSyncOptions } from "@openclaw/fs-safe/atomic";
import { isRootFileMissingFailure, openRootFileSync } from "../infra/boundary-file-read.js";
import { ConfigMutationConflictError } from "./mutation-conflict.js";
import { createConfigWriteAuthorityGuard } from "./write-authority.js";

export const CONFIG_BACKUP_COUNT = 5;

/** Prepare backup bytes without blocking unrelated Gateway requests. */
export async function prepareConfigFileWrite(
  params: {
    configPath: string;
    content: string;
    previousRaw: string | null;
    fsModule: typeof fs;
    assertCurrent?: () => void;
    destinationHardlinks?: "reject";
    durable?: boolean;
    requireBackup?: boolean;
  } & Pick<ReplaceFileAtomicSyncOptions, "assertBeforeMutation" | "onDestinationState">,
) {
  const { configPath, fsModule } = params;
  if (params.requireBackup && params.previousRaw === null) {
    throw new Error("Required config backup has no existing source");
  }
  const assertCurrent = createConfigWriteAuthorityGuard(params.assertCurrent);
  const assertBeforeMutation = createConfigWriteAuthorityGuard(
    params.assertBeforeMutation ?? assertCurrent,
  );
  assertCurrent?.();
  let backup: Awaited<ReturnType<typeof tempFile>> | undefined;
  try {
    if (params.previousRaw !== null) {
      backup = await tempFile({
        rootDir: path.dirname(configPath),
        prefix: "openclaw-config-backup",
        fileName: "original",
      });
      assertCurrent?.();
      await using handle = await fsModule.promises.open(backup.path, "wx", 0o600);
      assertCurrent?.();
      await handle.writeFile(params.previousRaw, "utf8");
      assertCurrent?.();
      if (params.durable) {
        await handle.sync();
        assertCurrent?.();
      }
    }
  } catch (error) {
    let cleanupFailure: { error: unknown } | undefined;
    try {
      await backup?.[Symbol.asyncDispose]();
    } catch (cleanupError) {
      cleanupFailure = { error: cleanupError };
    }
    if (cleanupFailure) {
      throw new AggregateError(
        [error, cleanupFailure.error],
        "Config backup preparation and cleanup failed",
        { cause: error },
      );
    }
    backup = undefined;
    if (params.requireBackup) {
      throw error;
    }
    // Backup creation remains best effort; failed preparation never consumes history.
    assertCurrent?.();
  }
  return {
    publish() {
      return replaceFileAtomicSync({
        filePath: configPath,
        content: params.content,
        dirMode: 0o700,
        mode: 0o600,
        copyFallbackOnPermissionError: true,
        destinationHardlinks: params.destinationHardlinks,
        syncTempFile: params.durable,
        syncParentDir: params.durable,
        fileSystem: fsModule,
        throwOnCleanupError: true,
        assertBeforeMutation,
        onDestinationState: params.onDestinationState,
        beforeRename: () => {
          if (!backup) {
            return;
          }
          const openBackupArtifact = (absolutePath: string) => {
            const opened = openRootFileSync({
              absolutePath,
              rootPath: path.dirname(configPath),
              boundaryLabel: "config backup directory",
              ioFs: fsModule,
            });
            return {
              ...opened,
              [Symbol.dispose]() {
                if (opened.ok) {
                  fsModule.closeSync(opened.fd);
                }
              },
            };
          };
          const captureBackupIdentity = (
            filePath: string,
            fd: number | undefined,
            role: "source" | "destination",
          ) => {
            const captured =
              fd === undefined ? undefined : fsModule.fstatSync(fd, { bigint: true });
            return () => {
              const current = fsModule.lstatSync(filePath, {
                bigint: true,
                throwIfNoEntry: role === "source",
              });
              const held = fd === undefined ? undefined : fsModule.fstatSync(fd, { bigint: true });
              if (
                captured
                  ? [current, held].some(
                      (entry) =>
                        !entry ||
                        !entry.isFile() ||
                        entry.nlink !== 1n ||
                        entry.dev !== captured.dev ||
                        entry.ino !== captured.ino,
                    )
                  : current
              ) {
                throw new ConfigMutationConflictError(`config backup ${role} changed`, {
                  retryable: false,
                });
              }
            };
          };
          const mutateBackupArtifact = (from: string, to?: string, mustExist = false) => {
            assertBeforeMutation();
            try {
              using destination = to ? openBackupArtifact(to) : undefined;
              if (destination && !destination.ok && !isRootFileMissingFailure(destination)) {
                if (params.requireBackup) {
                  throw new Error("Required config backup destination is unavailable");
                }
                return;
              }
              using source = openBackupArtifact(from);
              if (!source.ok) {
                if (params.requireBackup && (mustExist || !isRootFileMissingFailure(source))) {
                  throw new Error("Required config backup source is unavailable");
                }
                return;
              }
              const assertSource = captureBackupIdentity(source.path, source.fd, "source");
              const assertDestination = to
                ? captureBackupIdentity(
                    to,
                    destination?.ok ? destination.fd : undefined,
                    "destination",
                  )
                : undefined;
              const assertBackupCurrent = () => {
                assertBeforeMutation();
                assertSource();
                assertDestination?.();
              };
              assertBackupCurrent();
              if (to) {
                fsModule.fchmodSync(source.fd, 0o600);
                assertBackupCurrent();
                fsModule.renameSync(source.path, to);
              } else {
                fsModule.unlinkSync(source.path);
              }
            } catch (error) {
              let authorityFailure: { error: unknown } | undefined;
              try {
                assertBeforeMutation();
              } catch (authorityError) {
                authorityFailure = { error: authorityError };
              }
              if (authorityFailure) {
                throw new AggregateError(
                  [error, authorityFailure.error],
                  "Config backup mutation and authority check failed",
                  { cause: error },
                );
              }
              if (params.requireBackup || error instanceof ConfigMutationConflictError) {
                throw error;
              }
            }
          };
          const base = `${configPath}.bak`;
          mutateBackupArtifact(`${base}.${CONFIG_BACKUP_COUNT - 1}`);
          for (let index = CONFIG_BACKUP_COUNT - 2; index >= 0; index--) {
            const from = index === 0 ? base : `${base}.${index}`;
            mutateBackupArtifact(from, `${base}.${index + 1}`);
          }
          mutateBackupArtifact(backup.path, base, true);
          if (params.requireBackup) {
            // Retain and sync the recovery name before publishing new config bytes.
            const directoryFd = fsModule.openSync(path.dirname(configPath), "r");
            let primaryFailure: { error: unknown } | undefined;
            let closeFailure: { error: unknown } | undefined;
            try {
              assertBeforeMutation();
              fsModule.fsyncSync(directoryFd);
              assertBeforeMutation();
            } catch (error) {
              primaryFailure = { error };
            } finally {
              try {
                fsModule.closeSync(directoryFd);
              } catch (error) {
                closeFailure = { error };
              }
            }
            if (primaryFailure && closeFailure) {
              throw new AggregateError(
                [primaryFailure.error, closeFailure.error],
                "Config backup sync and close failed",
                { cause: primaryFailure.error },
              );
            }
            if (primaryFailure) {
              throw primaryFailure.error;
            }
            if (closeFailure) {
              throw closeFailure.error;
            }
          }
        },
      });
    },
    async [Symbol.asyncDispose]() {
      await backup?.[Symbol.asyncDispose]();
    },
  };
}

interface PreUpdateSnapshotFs {
  writeFile: (
    path: string,
    content: string,
    options: { encoding: "utf-8"; mode: number; flag: "w" },
  ) => Promise<void>;
  readFile: (path: string, encoding: "utf-8") => Promise<string>;
  existsSync: (path: string) => boolean;
}

const preUpdateConfigSnapshotsWritten = new Set<string>();

/**
 * Captures the first on-disk config state for an update attempt.
 *
 * The snapshot is outside the rotating `.bak` ring so repeated writes during
 * one process keep an operator-visible rollback point for the original file.
 */
export async function createPreUpdateConfigSnapshot(params: {
  configPath: string;
  fs: PreUpdateSnapshotFs;
}): Promise<void> {
  if (!params.fs.existsSync(params.configPath)) {
    return;
  }
  const snapshotKey = path.resolve(params.configPath);
  if (preUpdateConfigSnapshotsWritten.has(snapshotKey)) {
    return;
  }
  // Mark before I/O so concurrent callers coalesce onto the in-flight snapshot attempt.
  preUpdateConfigSnapshotsWritten.add(snapshotKey);
  const snapshotPath = `${params.configPath}.pre-update`;
  try {
    const content = await params.fs.readFile(params.configPath, "utf-8");
    await params.fs.writeFile(snapshotPath, content, {
      encoding: "utf-8",
      mode: 0o600,
      flag: "w",
    });
  } catch {
    // Best-effort: let the update continue, but allow its later snapshot pass to retry.
    preUpdateConfigSnapshotsWritten.delete(snapshotKey);
  }
}
