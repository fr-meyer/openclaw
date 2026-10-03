import type { DatabaseSync } from "node:sqlite";
import { executeSqliteQuerySync, getNodeSqliteKysely } from "../../infra/kysely-sync.js";
import type { DB } from "../../state/openclaw-state-db.generated.js";
import { collectLiveRunLeases, worktreeRunLeaseScope } from "./run-lease-owner.js";
import type { ManagedWorktreeOwnerKind } from "./types.js";

export type WorktreeRunLeaseExpectedAuthority = Readonly<{
  ownerKind: ManagedWorktreeOwnerKind;
  ownerId: string;
  repoFingerprint: string;
  path: string;
}>;

export type WorktreeRunLeaseRowInput = {
  worktreeId: string;
  token: string;
  pid: number;
  startTime: number | null;
  now: number;
  exclusive?: true;
  expectedAuthority?: WorktreeRunLeaseExpectedAuthority;
};

export function admitWorktreeRunLeaseInDatabase(
  db: DatabaseSync,
  params: WorktreeRunLeaseRowInput,
): void {
  const k = getNodeSqliteKysely<Pick<DB, "worktrees" | "state_leases">>(db);
  const scope = worktreeRunLeaseScope(params.worktreeId);
  const record = executeSqliteQuerySync(
    db,
    k
      .selectFrom("worktrees")
      .select(["path", "repo_fingerprint", "owner_kind", "owner_id", "removed_at"])
      .where("id", "=", params.worktreeId),
  ).rows[0];
  const worktreePath = record?.path ?? params.worktreeId;
  if (!record || record.removed_at != null) {
    throw new Error(`managed worktree was removed: ${worktreePath}`);
  }
  const expected = params.expectedAuthority;
  if (expected) {
    const currentOwners = executeSqliteQuerySync(
      db,
      k
        .selectFrom("worktrees")
        .select(["id", "created_at"])
        .where("owner_kind", "=", expected.ownerKind)
        .where("owner_id", "=", expected.ownerId)
        .where("removed_at", "is", null)
        .orderBy("created_at", "desc")
        .limit(2),
    ).rows;
    const latestOwner = currentOwners[0];
    if (
      latestOwner?.id !== params.worktreeId ||
      (currentOwners[1] && currentOwners[1].created_at === latestOwner?.created_at) ||
      record.owner_kind !== expected.ownerKind ||
      record.owner_id !== expected.ownerId ||
      record.repo_fingerprint !== expected.repoFingerprint ||
      record.path !== expected.path
    ) {
      throw new Error(`managed worktree is no longer authoritative: ${worktreePath}`);
    }
  }
  const { removingToken, liveCount, exclusive } = collectLiveRunLeases(db, k, scope, {});
  if (removingToken !== undefined) {
    throw new Error(`managed worktree was removed: ${worktreePath}`);
  }
  if (exclusive || (params.exclusive && liveCount > 0)) {
    throw new Error("The worktree is in use; wait for its current run or publication to finish.");
  }
  executeSqliteQuerySync(
    db,
    k.insertInto("state_leases").values({
      scope,
      lease_key: params.token,
      owner: `${params.pid}:${params.startTime ?? ""}`,
      expires_at: null,
      heartbeat_at: null,
      payload_json: JSON.stringify({
        pid: params.pid,
        starttime: params.startTime ?? undefined,
        ...(params.exclusive ? { exclusive: true } : {}),
      }),
      created_at: params.now,
      updated_at: params.now,
    }),
  );
}

export function releaseWorktreeRunLeaseInDatabase(
  db: DatabaseSync,
  worktreeId: string,
  token: string,
): void {
  executeSqliteQuerySync(
    db,
    getNodeSqliteKysely<Pick<DB, "state_leases">>(db)
      .deleteFrom("state_leases")
      .where("scope", "=", worktreeRunLeaseScope(worktreeId))
      .where("lease_key", "=", token),
  );
}
