import type { MemoryEmbeddingBatchSubmissionLifecycle } from "openclaw/plugin-sdk/memory-core-host-engine-embeddings";
import type {
  MemoryBatchSubmissionCommand, MemoryBatchSubmissionIdentity,
  MemoryBatchSubmissionRequest, MemoryBatchSubmissionReply, MemoryBatchSubmissionStatus,
} from "./manager-batch-submission-task.js";

/** Transport and published facts only. Durable decisions execute in the native SQLite worker. */
export class MemoryBatchSubmissionOwner {
  private status: MemoryBatchSubmissionStatus;
  private pendingKeys: string[] = [];
  private statusVersion = 0;
  private settled: Promise<void> = Promise.resolve();
  constructor(private readonly execute: (request: MemoryBatchSubmissionCommand) => Promise<MemoryBatchSubmissionReply>) {}
  captureStatusVersion(): number { return this.statusVersion; }
  installStatus(status: MemoryBatchSubmissionStatus, version: number): void {
    if (version === this.statusVersion) { this.status = status; }
  }
  readStatus(): MemoryBatchSubmissionStatus { return this.status; }
  private run(request: MemoryBatchSubmissionRequest) {
    const operation = this.settled.then(async () => {
      const reply = await this.execute({ ...request, pendingKeys: this.pendingKeys });
      this.statusVersion += 1;
      this.status = reply.status;
      this.pendingKeys = reply.pendingKeys;
      return reply;
    });
    this.settled = operation.then(() => undefined, () => undefined);
    return operation;
  }
  async assertReady(): Promise<void> { await this.run({ kind: "assert" }); }
  async commit(): Promise<void> { await this.run({ kind: "commit" }); }
  async clear(): Promise<boolean> {
    const reply = await this.run({ kind: "clear" });
    if (reply.kind !== "clear") { throw new Error("Invalid native quarantine clear reply"); }
    return reply.value;
  }
  createLifecycle(identity: MemoryBatchSubmissionIdentity): MemoryEmbeddingBatchSubmissionLifecycle {
    return {
      started: async (...args) => {
        const reply = await this.run({ kind: "started", identity, args });
        if (reply.kind !== "started") { throw new Error("Invalid native started reply"); }
        return reply.value;
      },
      accepted: async (...args) => {
        const reply = await this.run({ kind: "accepted", identity, args });
        if (reply.kind !== "accepted") { throw new Error("Invalid native accepted reply"); }
        return reply.value;
      },
      rejected: async (...args) => {
        const reply = await this.run({ kind: "rejected", identity, args });
        if (reply.kind !== "rejected") { throw new Error("Invalid native rejected reply"); }
        return reply.value;
      },
      resumeAccepted: async (...args) => {
        const reply = await this.run({ kind: "resumeAccepted", identity, args });
        if (reply.kind !== "resumeAccepted") { throw new Error("Invalid native resume reply"); }
        return reply.value;
      },
      listAccepted: async (...args) => {
        const reply = await this.run({ kind: "listAccepted", identity, args });
        if (reply.kind !== "listAccepted") { throw new Error("Invalid native listAccepted reply"); }
        return reply.value;
      },
      publishRecovered: async (...args) => {
        const reply = await this.run({ kind: "publishRecovered", identity, args });
        if (reply.kind !== "publishRecovered") { throw new Error("Invalid native publishRecovered reply"); }
        return reply.value;
      },
    };
  }
}
