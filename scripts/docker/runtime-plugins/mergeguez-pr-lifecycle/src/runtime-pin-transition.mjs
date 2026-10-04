import { createHash } from "node:crypto";
import { constants } from "node:fs";
import fs from "node:fs/promises";
import path from "node:path";

const PLUGIN_ID = "mergeguez-pr-lifecycle";
const HASH = /^[a-f0-9]{64}$/;
const validHash = (value) => typeof value === "string" && HASH.test(value);
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
const COMMON = Object.freeze({
  "index.mjs": "bb9096ec84a7047b016e4a4fedfce8e74be09d5253cd1391f1526ed83560c145",
  "src/controller.mjs": "c3d63b3c567541f72fb33c6982b41d4d5e4efa7fdd2d43ba5d7d14e624ebdbfc",
  "src/http.mjs": "7b4e7922ae90a412ff675c1091d8e97ece1160db215ce7fec052166633c82ee1",
});
const SOURCE_QUALIFIED_CANDIDATE = Object.freeze({
  version: "0.1.1",
  sourceCommit: "1e197fa258704d70e17a9efd831b2e3ecbc6e6f4",
  files: Object.freeze({
    ...COMMON,
    "src/runtime.mjs": "d9ae3b77db061d30e10657133a376b3da99234367bdfb95ab1266ca9ed558569",
    "package.json": "25dd78b7559c6e32cc94658eea299c2db16999bb10991da86ac88c5ec520a97c",
    "openclaw.plugin.json": "7e59281147e003e735b63f2bc35aacfda065ccd27b37a62b6dcb46bb99a9f3b1",
  }),
});
export const INSTALLED_PUBLISHER_PIN_PAIR = Object.freeze({
  predecessor: Object.freeze({
    version: "0.1.0",
    files: Object.freeze({
      ...COMMON,
      "src/runtime.mjs": "7e6cbe8ab75213049fc21f85dc5df4b2c740ac9cfd35edd1d4aadc4a92167e74",
      "package.json": "a90a0c2e8d79a816858f804045628fbaac04675cbc3745270f8d66e22d99ad4a",
      "openclaw.plugin.json": "d34efddbd8f10288226295d6aabfbd0e7e5562332007dcc66bf2b1c70d25e3e7",
    }),
  }),
  sourceQualifiedCandidate: SOURCE_QUALIFIED_CANDIDATE,
  candidate: Object.freeze({
    version: SOURCE_QUALIFIED_CANDIDATE.version,
    sourceCommit: "14a2507d86423f1881d4aad79af634623aacda60",
    files: Object.freeze({
      ...SOURCE_QUALIFIED_CANDIDATE.files,
      "src/runtime.mjs": "d6d4d3859ff676de0bbd2b94b0e84d4a4d07977171e1754040d12fb0c9082b0b",
    }),
  }),
});

export class PublisherPinTransitionError extends Error {
  constructor(code, receipt, cause) {
    super(code, cause === undefined ? undefined : { cause });
    this.name = "PublisherPinTransitionError";
    this.code = code;
    this.receipt = Object.freeze(receipt);
  }
}

// Artifact bytes are evidence only. The release owner separately owns evaluated
// applier custody, current admission and the one-writer cutover decision.
export async function readPublisherArtifactBytes(absolutePath) {
  if ((await fs.realpath(absolutePath)) !== absolutePath) {
    throw new Error("publisher_artifact_symlink");
  }
  const handle = await fs.open(
    absolutePath,
    constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
  );
  let primary;
  let closeFailure;
  let result;
  try {
    const before = await handle.stat({ bigint: true });
    if (!before.isFile() || before.nlink !== 1n || before.size > 1048576n) {
      throw new Error("publisher_artifact_not_bounded_regular_file");
    }
    const bytes = await handle.readFile();
    const after = await handle.stat({ bigint: true });
    if (
      bytes.length !== Number(before.size) ||
      before.size !== after.size ||
      before.mtimeNs !== after.mtimeNs ||
      before.ctimeNs !== after.ctimeNs
    ) {
      throw new Error("publisher_artifact_changed_during_read");
    }
    result = bytes;
  } catch (error) {
    primary = { error };
  } finally {
    try {
      await handle.close();
    } catch (error) {
      closeFailure = { error };
    }
  }
  if (primary && closeFailure) {
    throw new AggregateError(
      [primary.error, closeFailure.error],
      "publisher_artifact_read_and_close_failed",
      {
        cause: primary.error,
      },
    );
  }
  if (primary) {
    throw primary.error;
  }
  if (closeFailure) {
    throw closeFailure.error;
  }
  return result;
}

/**
 * Local release/Doctor operation, never a runtime registration or auto migration.
 * SDK owns config locking, CAS, validation, backup and publication. Returned
 * receipts contain no config, secrets, raw paths, or raw SDK error messages.
 */
export function createInstalledPublisherPinTransition({
  authority,
  loadConfigMutation = () => import("openclaw/plugin-sdk/config-mutation"),
  readArtifact = readPublisherArtifactBytes,
}) {
  if (typeof authority?.assertCurrent !== "function") {
    throw new Error("publisher_release_owner_required");
  }
  const synchronousAssertion = (callback) => {
    const captured = callback.bind(authority);
    return () => {
      const result = captured();
      if (result !== undefined) {
        // Observe an invalid async guard's rejection, then refuse synchronously.
        // Its eventual settlement cannot authorize this operation.
        if (typeof result?.then === "function") {
          void Promise.resolve(result).catch(() => undefined);
        }
        throw new Error("publisher_release_assertion_must_be_synchronous");
      }
    };
  };
  const assertCurrent = synchronousAssertion(authority.assertCurrent);
  const assertRollbackSafe =
    typeof authority.assertRollbackSafe === "function"
      ? synchronousAssertion(authority.assertRollbackSafe)
      : undefined;
  return async (request) => {
    let phase = "preflight";
    let committedConfigHash = null;
    let captured = {};
    const receipt = (status, configHash = committedConfigHash ?? captured.expectedConfigHash) => ({
      schema: "publisher-runtime-pin-transition/v1",
      direction: ["forward", "reverse"].includes(captured.direction) ? captured.direction : null,
      status,
      configHash: validHash(configHash) ? configHash : null,
      inputConfigHash: validHash(captured.expectedConfigHash) ? captured.expectedConfigHash : null,
      committedConfigHash,
      mutationAttempted: phase !== "preflight",
      runtimePathSha256:
        typeof captured.expectedRuntimePath === "string"
          ? sha256(captured.expectedRuntimePath)
          : null,
      runtimeActivation: false,
      databaseRollback: false,
    });
    const refuse = (code) => {
      throw new PublisherPinTransitionError(code, receipt("refused"));
    };
    let pair;
    try {
      assertCurrent();
      if (!request || typeof request !== "object" || Array.isArray(request)) {
        refuse("PIN_REQUEST_INVALID");
      }
      captured = {
        direction: request.direction,
        expectedConfigHash: request.expectedConfigHash,
        expectedConfigPath: request.expectedConfigPath,
        expectedRuntimePath: request.expectedRuntimePath,
      };
      if (!["forward", "reverse"].includes(captured.direction)) {
        refuse("PIN_DIRECTION_INVALID");
      }
      if (!validHash(captured.expectedConfigHash)) {
        refuse("PIN_CONFIG_REVISION_REQUIRED");
      }
      if (
        typeof captured.expectedConfigPath !== "string" ||
        !path.isAbsolute(captured.expectedConfigPath)
      ) {
        refuse("PIN_CONFIG_PATH_REQUIRED");
      }
      const runtimePath = captured.expectedRuntimePath;
      if (
        typeof runtimePath !== "string" ||
        !path.isAbsolute(runtimePath) ||
        path.normalize(runtimePath) !== runtimePath ||
        !runtimePath.endsWith("/src/runtime.mjs")
      ) {
        refuse("PIN_RUNTIME_PATH_INVALID");
      }
      pair =
        captured.direction === "forward"
          ? [INSTALLED_PUBLISHER_PIN_PAIR.predecessor, INSTALLED_PUBLISHER_PIN_PAIR.candidate]
          : [INSTALLED_PUBLISHER_PIN_PAIR.candidate, INSTALLED_PUBLISHER_PIN_PAIR.predecessor];
      const fromHash = pair[0].files["src/runtime.mjs"];
      const toHash = pair[1].files["src/runtime.mjs"];
      const assertReleaseCurrent = () => {
        assertCurrent();
        if (captured.direction === "reverse") {
          if (!assertRollbackSafe) {
            refuse("PIN_ROLLBACK_ADMISSION_REQUIRED");
          }
          assertRollbackSafe();
        }
      };
      const verifyTarget = async () => {
        assertReleaseCurrent();
        const root = path.dirname(path.dirname(runtimePath));
        for (const [relative, digest] of Object.entries(pair[1].files)) {
          const bytes = await readArtifact(path.join(root, relative));
          assertReleaseCurrent();
          if (sha256(bytes) !== digest) {
            refuse("PIN_TARGET_PACKAGE_MISMATCH");
          }
        }
      };
      const validateSnapshot = (snapshot, hash) => {
        if (
          !snapshot?.exists ||
          !snapshot.valid ||
          snapshot.path !== captured.expectedConfigPath ||
          hash !== captured.expectedConfigHash
        ) {
          refuse("PIN_STALE_CONFIG");
        }
        // This repair is root-file-only; an include graph needs its own complete
        // backup admission rather than treating a root backup as full coverage.
        if (snapshot.includeProvenance?.length || snapshot.includedPaths?.length) {
          refuse("PIN_INCLUDED_CONFIG_UNSUPPORTED");
        }
        const config = snapshot.sourceConfig?.plugins?.entries?.[PLUGIN_ID]?.config;
        if (!config || config.expectedRuntimePath !== runtimePath) {
          refuse("PIN_PATH_PREIMAGE_MISMATCH");
        }
        if (![fromHash, toHash].includes(config.expectedRuntimeSha256)) {
          refuse("PIN_HASH_PREIMAGE_MISMATCH");
        }
        return config;
      };
      await verifyTarget();
      const sdk = await loadConfigMutation();
      assertReleaseCurrent();
      if (sdk.CONFIG_MUTATION_CAPABILITIES?.requireDurableBackup !== 1) {
        refuse("PIN_REQUIRED_BACKUP_SDK_UNSUPPORTED");
      }
      const prepared = await sdk.readConfigFileSnapshotForWrite();
      assertReleaseCurrent();
      const current = validateSnapshot(prepared.snapshot, prepared.snapshot.hash);
      if (current.expectedRuntimeSha256 === toHash) {
        return Object.freeze(receipt("already-target"));
      }
      phase = "mutation";
      const result = await sdk.mutateConfigFile({
        base: "source",
        baseHash: captured.expectedConfigHash,
        afterWrite: {
          mode: "none",
          reason: "publisher release pin transition; activation is separately admitted",
        },
        writeOptions: {
          expectedConfigPath: captured.expectedConfigPath,
          requireBackup: true,
          skipOutputLogs: true,
          auditOrigin: "cli",
          assertCurrent: assertReleaseCurrent,
          beforeCommit: verifyTarget,
        },
        mutate: (draft, context) => {
          assertReleaseCurrent();
          const config = validateSnapshot(context.snapshot, context.previousHash);
          if (config.expectedRuntimeSha256 !== fromHash) {
            refuse("PIN_CONCURRENT_TRANSITION");
          }
          draft.plugins.entries[PLUGIN_ID].config.expectedRuntimeSha256 = toHash;
          phase = "commit-pending";
        },
      });
      phase = "committed";
      if (!validHash(result.persistedHash)) {
        throw new Error("publisher_config_commit_identity_missing");
      }
      committedConfigHash = result.persistedHash;
      await verifyTarget();
      return Object.freeze(receipt("applied", result.persistedHash));
    } catch (error) {
      if (error instanceof PublisherPinTransitionError && phase === "preflight") {
        throw error;
      }
      // Any SDK attempt or post-commit failure requires an owner reread, even if
      // the SDK reports compensation. Never infer absence or blindly retry.
      const outcome = receipt(phase === "preflight" ? "refused" : "unknown");
      if (["restored", "not-restored", "unknown"].includes(error?.rollbackStatus)) {
        outcome.ownerRollbackStatus = error.rollbackStatus;
      }
      if (["complete", "partial"].includes(error?.publication)) {
        outcome.ownerPublication = error.publication;
      }
      throw new PublisherPinTransitionError(
        phase === "preflight" ? "PIN_PREFLIGHT_FAILED" : "PIN_TRANSITION_UNKNOWN",
        outcome,
        error,
      );
    }
  };
}
