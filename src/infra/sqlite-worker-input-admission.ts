import { createDeferredCore } from "../shared/deferred.js";
import { runQueuedStoreWrite, type StoreWriterQueue } from "../shared/store-writer-queue.js";
import type {
  SqliteWorkerInputPreparation,
  SqliteWorkerInputRetention,
} from "./sqlite-worker-broker.types.js";
import { SqliteWorkerError } from "./sqlite-worker-contract.js";

/** Retained inputs share the broker budget before they become queued jobs. */
export class SqliteWorkerInputAdmission {
  private bytes = 0;
  private inputPreparationGeneration = {};
  private readonly inputPreparations = new Set<Promise<void>>();
  private readonly openQueue = new Map<string, StoreWriterQueue>();
  private readonly pendingOpens = new Set<Promise<unknown>>();

  constructor(
    private readonly owner: {
      queuedBytes(): number;
      isClosing(): boolean;
      maxQueuedBytes: number;
      maxQueuedInputBytes: number;
      maxMessageBytes: number;
    },
  ) {}

  get retainedBytes(): number {
    return this.bytes;
  }

  retain(bytes: number): () => void {
    this.bytes += bytes;
    let released = false;
    return () => {
      if (!released) {
        released = true;
        this.bytes -= bytes;
      }
    };
  }

  open<T>(
    bytes: number,
    prepare: () => Promise<{ keys?: readonly string[]; dispatch: () => Promise<T> }>,
    signal?: AbortSignal,
  ): Promise<T> {
    if (
      bytes > this.owner.maxMessageBytes ||
      this.owner.queuedBytes() + this.bytes + bytes > this.owner.maxQueuedBytes
    ) {
      return Promise.reject(
        new SqliteWorkerError("SQLite worker open input capacity reached", "overloaded"),
      );
    }
    const release = this.retain(bytes);
    // Identity I/O cannot reorder conflicting callers. Enqueue in request order,
    // but release preparation before waiting for any native opening to settle.
    const prepared = Promise.resolve().then(() =>
      runQueuedStoreWrite({
        queues: this.openQueue,
        storePath: "sqlite-open-preparation",
        label: "SQLite worker open identity",
        signal,
        fn: async () => {
          signal?.throwIfAborted();
          const { keys, dispatch } = await prepare();
          signal?.throwIfAborted();
          return {
            openingPromise: runQueuedStoreWrite({
              queues: this.openQueue,
              storePath: "sqlite-open",
              label: "SQLite worker open",
              keys,
              fn: dispatch,
              signal,
            }),
          };
        },
      }),
    );
    const opening = prepared
      .then(({ openingPromise }) => openingPromise)
      .finally(() => {
        release();
        this.pendingOpens.delete(opening);
      });
    // Include identity preparation, before it can publish a keyed or exclusive lane.
    this.pendingOpens.add(opening);
    return opening;
  }

  async joinOpens(): Promise<void> {
    while (this.pendingOpens.size) {
      await Promise.allSettled(this.pendingOpens);
    }
  }

  invalidatePreparations(): void {
    this.inputPreparationGeneration = {};
  }

  async joinPreparations(): Promise<void> {
    await Promise.allSettled(this.inputPreparations);
  }

  reserveInputPreparation(
    inputBytes: number,
    retention: SqliteWorkerInputRetention = "stream",
  ): SqliteWorkerInputPreparation {
    if (!Number.isSafeInteger(inputBytes) || inputBytes < 0) {
      throw new RangeError("SQLite worker input bytes must be a non-negative safe integer");
    }
    if (this.owner.isClosing()) {
      throw new SqliteWorkerError("SQLite worker host is closing", "closed");
    }
    const bytes =
      retention === "stream" && inputBytes > this.owner.maxQueuedInputBytes
        ? this.owner.maxMessageBytes
        : inputBytes;
    if (this.owner.queuedBytes() + this.bytes + bytes > this.owner.maxQueuedBytes) {
      throw new SqliteWorkerError("SQLite worker input preparation capacity reached", "overloaded");
    }
    const generation = this.inputPreparationGeneration;
    this.bytes += bytes;
    const settled = createDeferredCore();
    this.inputPreparations.add(settled.promise);
    let handedOff = false;
    const release = () => {
      if (this.inputPreparations.delete(settled.promise)) {
        this.bytes -= bytes;
        settled.resolve();
      }
    };
    const assertCurrent = () => {
      if (
        !handedOff &&
        (!this.inputPreparations.has(settled.promise) ||
          this.owner.isClosing() ||
          generation !== this.inputPreparationGeneration)
      ) {
        throw new SqliteWorkerError("SQLite worker input preparation is closed", "closed");
      }
    };
    return {
      assertCurrent,
      handoff: (dispatch) => {
        try {
          if (!this.inputPreparations.has(settled.promise)) {
            throw new SqliteWorkerError("SQLite worker input preparation is closed", "closed");
          }
          assertCurrent();
        } catch (error) {
          release();
          throw error;
        }
        // Enqueue takes custody in this same synchronous turn, including its oversized checks.
        handedOff = true;
        release();
        return dispatch();
      },
      release,
    };
  }
}
