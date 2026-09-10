// Memory Core plugin module owns durable native-batch submission quarantine state.
import type { DatabaseSync } from "node:sqlite";
import type { MemoryEmbeddingBatchSubmissionLifecycle } from "openclaw/plugin-sdk/memory-core-host-engine-embeddings";
import { runSqliteImmediateTransactionSync } from "openclaw/plugin-sdk/sqlite-runtime";

const BATCH_SUBMISSION_QUARANTINE_META_KEY = "memory_batch_submission_quarantine_v1";

const MEMORY_BATCH_SUBMISSION_RECOVERY_ACTION =
  "Reconcile or cancel the listed provider jobs, then run openclaw memory index --force --clear-batch-quarantine.";

export type MemoryBatchSubmissionRecord = {
  provider: string;
  submissionId: string;
  batchName?: string;
  startedAt: string;
};

type MemoryBatchSubmissionQuarantine = {
  version: 1;
  submissions: MemoryBatchSubmissionRecord[];
};

export type MemoryBatchSubmissionQuarantineStatus = {
  malformed: boolean;
  submissions: MemoryBatchSubmissionRecord[];
  recoveryAction: string;
};

function buildBatchSubmissionKey(provider: string, submissionId: string): string {
  return `${provider}\u0000${submissionId}`;
}

function isNonEmptyBoundedString(value: unknown, maxLength: number): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= maxLength;
}

function parseBatchSubmissionQuarantine(value: string): MemoryBatchSubmissionQuarantine | null {
  try {
    // SAFETY: parsed fields stay unknown and are validated below before use.
    const parsed = JSON.parse(value) as { version?: unknown; submissions?: unknown };
    if (parsed.version !== 1 || !Array.isArray(parsed.submissions)) {
      return null;
    }
    const submissions: MemoryBatchSubmissionRecord[] = [];
    for (const entry of parsed.submissions) {
      if (!entry || typeof entry !== "object") {
        return null;
      }
      // SAFETY: the object guard above permits unknown property inspection.
      const candidate = entry as Record<string, unknown>;
      if (
        !isNonEmptyBoundedString(candidate.provider, 100) ||
        !isNonEmptyBoundedString(candidate.submissionId, 200) ||
        !isNonEmptyBoundedString(candidate.startedAt, 100) ||
        (candidate.batchName !== undefined && !isNonEmptyBoundedString(candidate.batchName, 500))
      ) {
        return null;
      }
      submissions.push({
        provider: candidate.provider,
        submissionId: candidate.submissionId,
        startedAt: candidate.startedAt,
        ...(candidate.batchName ? { batchName: candidate.batchName } : {}),
      });
    }
    return { version: 1, submissions };
  } catch {
    return null;
  }
}

export class MemoryBatchSubmissionOwner {
  private readonly keysPendingCommit = new Set<string>();

  constructor(private readonly getDatabase: () => DatabaseSync) {}

  readStatus(): MemoryBatchSubmissionQuarantineStatus | undefined {
    const rowValue = this.getDatabase()
      .prepare(`SELECT value FROM memory_index_meta WHERE key = ?`)
      .get(BATCH_SUBMISSION_QUARANTINE_META_KEY);
    // SAFETY: this query selects exactly one SQLite value column.
    const row = rowValue as { value?: unknown } | undefined;
    if (!row) {
      return undefined;
    }
    if (typeof row.value !== "string") {
      return this.malformedStatus();
    }
    const parsed = parseBatchSubmissionQuarantine(row.value);
    if (!parsed || parsed.submissions.length === 0) {
      return this.malformedStatus();
    }
    return {
      malformed: false,
      submissions: parsed.submissions,
      recoveryAction: MEMORY_BATCH_SUBMISSION_RECOVERY_ACTION,
    };
  }

  assertReady(): void {
    const quarantine = this.readStatus();
    if (!quarantine) {
      return;
    }
    const detail = quarantine.malformed
      ? "the durable quarantine record is malformed"
      : `${quarantine.submissions.length} provider submission${quarantine.submissions.length === 1 ? "" : "s"} require reconciliation`;
    throw new Error(
      `memory embedding batch submission quarantined: ${detail}. ${quarantine.recoveryAction}`,
    );
  }

  clear(): boolean {
    const result = this.getDatabase()
      .prepare(`DELETE FROM memory_index_meta WHERE key = ?`)
      .run(BATCH_SUBMISSION_QUARANTINE_META_KEY);
    this.keysPendingCommit.clear();
    return result.changes > 0;
  }

  createLifecycle(provider: string): MemoryEmbeddingBatchSubmissionLifecycle {
    const remove = (submissionId: string) => {
      this.update((current) =>
        current.filter(
          (entry) => entry.provider !== provider || entry.submissionId !== submissionId,
        ),
      );
      this.keysPendingCommit.delete(buildBatchSubmissionKey(provider, submissionId));
    };
    return {
      started: async ({ submissionId }) => {
        if (!isNonEmptyBoundedString(submissionId, 200)) {
          throw new Error("memory embedding provider supplied an invalid batch submission id");
        }
        this.update((current) => {
          const foreignReservation = current.find(
            (entry) =>
              !this.keysPendingCommit.has(
                buildBatchSubmissionKey(entry.provider, entry.submissionId),
              ),
          );
          if (foreignReservation) {
            throw new Error(
              "memory embedding batch submission is already reserved by another sync",
            );
          }
          if (
            current.some(
              (entry) => entry.provider === provider && entry.submissionId === submissionId,
            )
          ) {
            throw new Error(`memory embedding batch submission id already exists: ${submissionId}`);
          }
          return [...current, { provider, submissionId, startedAt: new Date().toISOString() }];
        });
        this.keysPendingCommit.add(buildBatchSubmissionKey(provider, submissionId));
      },
      accepted: async ({ submissionId, batchName }) => {
        if (!isNonEmptyBoundedString(batchName, 500)) {
          throw new Error("memory embedding provider supplied an invalid batch resource name");
        }
        let found = false;
        this.update((current) =>
          current.map((entry) => {
            if (entry.provider !== provider || entry.submissionId !== submissionId) {
              return entry;
            }
            found = true;
            return { ...entry, batchName };
          }),
        );
        if (!found) {
          throw new Error(
            `memory embedding batch submission is not durably owned: ${submissionId}`,
          );
        }
      },
      rejected: async ({ submissionId }) => {
        remove(submissionId);
      },
    };
  }

  commit(): void {
    if (this.keysPendingCommit.size === 0) {
      return;
    }
    this.update((current) =>
      current.filter(
        (entry) =>
          !this.keysPendingCommit.has(buildBatchSubmissionKey(entry.provider, entry.submissionId)),
      ),
    );
    this.keysPendingCommit.clear();
  }

  private malformedStatus(): MemoryBatchSubmissionQuarantineStatus {
    return {
      malformed: true,
      submissions: [],
      recoveryAction: MEMORY_BATCH_SUBMISSION_RECOVERY_ACTION,
    };
  }

  private update(
    update: (current: MemoryBatchSubmissionRecord[]) => MemoryBatchSubmissionRecord[],
  ): void {
    const db = this.getDatabase();
    runSqliteImmediateTransactionSync(db, () => {
      const rowValue = db
        .prepare(`SELECT value FROM memory_index_meta WHERE key = ?`)
        .get(BATCH_SUBMISSION_QUARANTINE_META_KEY);
      // SAFETY: this query selects exactly one SQLite value column.
      const row = rowValue as { value?: unknown } | undefined;
      let current: MemoryBatchSubmissionRecord[] = [];
      if (row) {
        if (typeof row.value !== "string") {
          throw new Error("memory embedding batch quarantine record is malformed");
        }
        const parsed = parseBatchSubmissionQuarantine(row.value);
        if (!parsed) {
          throw new Error("memory embedding batch quarantine record is malformed");
        }
        current = parsed.submissions;
      }
      const next = update(current);
      if (next.length === 0) {
        db.prepare(`DELETE FROM memory_index_meta WHERE key = ?`).run(
          BATCH_SUBMISSION_QUARANTINE_META_KEY,
        );
        return;
      }
      const value = JSON.stringify({ version: 1, submissions: next });
      db.prepare(
        `INSERT INTO memory_index_meta (key, value) VALUES (?, ?)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
      ).run(BATCH_SUBMISSION_QUARANTINE_META_KEY, value);
    });
  }
}
