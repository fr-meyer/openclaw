import type { MemoryBatchSubmissionKernel } from "./manager-batch-submission-kernel.js";

type Lifecycle = ReturnType<MemoryBatchSubmissionKernel["createLifecycle"]>;
export type MemoryBatchSubmissionIdentity = Parameters<
  MemoryBatchSubmissionKernel["createLifecycle"]
>[0];
export type MemoryBatchSubmissionStatus = ReturnType<MemoryBatchSubmissionKernel["readStatus"]>;
export type MemoryBatchSubmissionRequest =
  | { kind: "assert" | "clear" | "commit" }
  | {
      kind: "started";
      identity: MemoryBatchSubmissionIdentity;
      args: Parameters<Lifecycle["started"]>;
    }
  | {
      kind: "accepted";
      identity: MemoryBatchSubmissionIdentity;
      args: Parameters<Lifecycle["accepted"]>;
    }
  | {
      kind: "rejected";
      identity: MemoryBatchSubmissionIdentity;
      args: Parameters<Lifecycle["rejected"]>;
    }
  | {
      kind: "resumeAccepted";
      identity: MemoryBatchSubmissionIdentity;
      args: Parameters<Lifecycle["resumeAccepted"]>;
    }
  | {
      kind: "listAccepted";
      identity: MemoryBatchSubmissionIdentity;
      args: Parameters<Lifecycle["listAccepted"]>;
    }
  | {
      kind: "publishRecovered";
      identity: MemoryBatchSubmissionIdentity;
      args: Parameters<Lifecycle["publishRecovered"]>;
    };
export type MemoryBatchSubmissionCommand = MemoryBatchSubmissionRequest & { pendingKeys: string[] };
type Snapshot = { status: MemoryBatchSubmissionStatus; pendingKeys: string[] };
export type MemoryBatchSubmissionReply =
  | (Snapshot & { kind: "assert" | "commit"; value: void })
  | (Snapshot & { kind: "clear"; value: boolean })
  | (Snapshot & { kind: "started"; value: ReturnType<Lifecycle["started"]> })
  | (Snapshot & { kind: "accepted"; value: ReturnType<Lifecycle["accepted"]> })
  | (Snapshot & { kind: "rejected"; value: ReturnType<Lifecycle["rejected"]> })
  | (Snapshot & { kind: "resumeAccepted"; value: ReturnType<Lifecycle["resumeAccepted"]> })
  | (Snapshot & { kind: "listAccepted"; value: ReturnType<Lifecycle["listAccepted"]> })
  | (Snapshot & { kind: "publishRecovered"; value: ReturnType<Lifecycle["publishRecovered"]> });
