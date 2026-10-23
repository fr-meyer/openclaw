import type { DatabaseSync } from "node:sqlite";
import { executeSqliteQuerySync, getNodeSqliteKysely } from "../../infra/kysely-sync.js";
import type { DB } from "../../state/openclaw-state-db.generated.js";
import { worktreeRegistryPublication } from "./registry-publication.js";
import { assertWorktreeRegistryPredicates } from "./registry-run-end.worker.js";
import { collectLiveRunLeases, worktreeRunLeaseScope } from "./run-lease-owner.js";
import type { ManagedWorktreeRecord } from "./types.js";

export type WorktreeRunLeaseRowInput = {
  worktreeId: string;
  token: string;
  pid: number;
  startTime: number | null;
  now: number;
  exclusive?: true;
  observed?: ManagedWorktreeRecord;
};

export function admitWorktreeRunLeaseInDatabase(
  db: DatabaseSync,
  params: WorktreeRunLeaseRowInput,
): void {
  const k = getNodeSqliteKysely<Pick<DB, "worktrees" | "state_leases">>(db);
  if (params.observed) {
    assertWorktreeRegistryPredicates(db, [{ kind: "binding", record: params.observed }]);
    const observed = params.observed;
    let owners = k
      .selectFrom("worktrees")
      .select(["id", "created_at"])
      .where("owner_kind", "=", observed.ownerKind)
      .where("repo_fingerprint", "=", observed.repoFingerprint)
      .where("path", "=", observed.path)
      .where("removed_at", "is", null);
    owners =
      observed.ownerId === undefined
        ? owners.where("owner_id", "is", null)
        : owners.where("owner_id", "=", observed.ownerId);
    const currentOwners = executeSqliteQuerySync(
      db,
      owners.orderBy("created_at", "desc").limit(2),
    ).rows;
    const latestOwner = currentOwners[0];
    if (
      latestOwner?.id !== observed.id ||
      (currentOwners[1] && currentOwners[1].created_at === latestOwner?.created_at)
    ) {
      throw new Error(`managed worktree is no longer authoritative: ${observed.path}`);
    }
  }
  const scope = worktreeRunLeaseScope(params.worktreeId);
  const record = executeSqliteQuerySync(
    db,
    k.selectFrom("worktrees").select(["path", "removed_at"]).where("id", "=", params.worktreeId),
  ).rows[0];
  const worktreePath = record?.path ?? params.worktreeId;
  if (!record || record.removed_at != null) {
    throw new Error(`managed worktree was removed: ${worktreePath}`);
  }
  const { removingToken, liveCount, exclusive } = collectLiveRunLeases(db, k, scope);
  if (removingToken !== undefined) {
    throw new Error(`managed worktree was removed: ${worktreePath}`);
  }
  if (exclusive || (params.exclusive && liveCount > 0)) {
    throw new Error("The worktree is in use; wait for its current run or publication to finish.");
  }
  const inserted = executeSqliteQuerySync(
    db,
    k
      .insertInto("state_leases")
      .values({
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
      })
      .returningAll(),
  ).rows;
  worktreeRegistryPublication.rows(db, inserted);
}

export function releaseWorktreeRunLeaseInDatabase(
  db: DatabaseSync,
  worktreeId: string,
  token: string,
): void {
  const removed = executeSqliteQuerySync(
    db,
    getNodeSqliteKysely<Pick<DB, "state_leases">>(db)
      .deleteFrom("state_leases")
      .where("scope", "=", worktreeRunLeaseScope(worktreeId))
      .where("lease_key", "=", token)
      .returning(["scope", "lease_key"]),
  ).rows;
  worktreeRegistryPublication.deleted(db, removed);
}
