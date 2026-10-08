// Physical custody and failure-preserving settlement for the existing reconcile owner.
import { readDatabasePathIdentitySync } from "../../infra/sqlite-worker-identity.js";
import {
  resolveOpenClawAgentSqlitePath,
  type OpenClawAgentDatabaseOptions,
} from "../../state/openclaw-agent-db.js";
import {
  captureOpenClawAgentDatabaseExecution,
  supportsOpenClawAgentDatabaseExecution,
  type OpenClawAgentDatabaseExecution,
} from "../../state/openclaw-agent-execution.js";

export type CapturedReconcileExecution = {
  owner: OpenClawAgentDatabaseExecution;
  readonly fileIdentity: { key: string; birthtime?: string } | undefined;
  assertCurrent(): void;
};

export function captureReconcileExecution(
  params: OpenClawAgentDatabaseOptions & {
    env: NodeJS.ProcessEnv;
    expectedFileIdentity?: { key: string; birthtime?: string };
  },
): CapturedReconcileExecution | undefined {
  const options = { ...params, path: resolveOpenClawAgentSqlitePath(params) };
  // Incognito, maintenance and deletion keep their explicitly retained native owners.
  // Worker failure never selects this branch after durable work has been admitted.
  if (!supportsOpenClawAgentDatabaseExecution(options)) {
    return undefined;
  }
  const identity = readDatabasePathIdentitySync(options.path);
  let fileIdentity = params.expectedFileIdentity
    ? Object.freeze({ ...params.expectedFileIdentity })
    : identity.key.startsWith("file:")
      ? Object.freeze({ key: identity.key, birthtime: identity.birthtime })
      : undefined;
  if (
    fileIdentity &&
    (identity.key !== fileIdentity.key || identity.birthtime !== fileIdentity.birthtime)
  ) {
    throw new Error("Transcript reconciliation lost its original physical database");
  }
  const owner = captureOpenClawAgentDatabaseExecution(
    options,
    fileIdentity
      ? {
          expectedIdentity: {
            kind: "file",
            physicalIdentity: fileIdentity.key.slice(5),
            birthtime: fileIdentity.birthtime,
            nativeLocation: options.path,
          },
        }
      : { expectedCreationIdentity: identity },
  );
  const assertCurrent = () => {
    owner.assertCurrent();
    const accepted = owner.fileIdentity;
    if (accepted) {
      fileIdentity ??= Object.freeze({
        key: `file:${accepted.physicalIdentity}`,
        birthtime: accepted.birthtime,
      });
    }
    const current = readDatabasePathIdentitySync(options.path);
    if (
      current.canonicalPath !== identity.canonicalPath ||
      current.key !== (fileIdentity?.key ?? identity.key) ||
      current.birthtime !== (fileIdentity?.birthtime ?? identity.birthtime)
    ) {
      throw new Error("Transcript reconciliation lost its captured physical database target");
    }
  };
  return {
    owner,
    get fileIdentity() {
      assertCurrent();
      return fileIdentity;
    },
    assertCurrent,
  };
}

export async function releaseReconcileResources(
  release: () => void | Promise<void>,
  failure?: { error: unknown },
): Promise<void> {
  try {
    await release();
  } catch (error) {
    throw failure
      ? new AggregateError([failure.error, error], "Transcript reconciliation cleanup failed", {
          cause: failure.error,
        })
      : error;
  }
}

export async function withReconcileCleanup<T>(
  operation: () => Promise<T>,
  release: () => void | Promise<void>,
): Promise<T> {
  let failure: { error: unknown } | undefined;
  try {
    return await operation();
  } catch (error) {
    failure = { error };
    throw error;
  } finally {
    await releaseReconcileResources(release, failure);
  }
}
