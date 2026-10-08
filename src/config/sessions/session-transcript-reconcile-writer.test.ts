import { afterEach, expect, it, vi } from "vitest";
import { hasSqliteWorkerOutcomeUnknown } from "../../infra/sqlite-worker-contract.js";
import { createSqliteWorkerOperationAdmission } from "../../infra/sqlite-worker-operation-admission.js";
import type {
  SqliteWorkerNativeSettlement,
  SqliteWorkerOperationSettlement,
} from "../../infra/sqlite-worker-operation-settlement.js";
import { sessionChanges } from "../../sessions/session-row-changes.js";
import { createDeferredCore } from "../../shared/deferred.js";
import type { AgentDatabaseRequestExecutionSource } from "../../state/openclaw-agent-execution-contract.js";
import type { AgentDatabaseExecutionScope } from "../../state/openclaw-agent-execution-native.js";
import type { OpenClawAgentDatabaseExecution } from "../../state/openclaw-agent-execution.js";
import type { withSessionEntryWorker } from "./session-accessor.sqlite-replacement-worker.js";
import type { SessionEntryCommitContext } from "./session-accessor.types.js";
import type {
  SessionTranscriptReconcileWrite,
  SessionTranscriptReconcileWriteResult,
} from "./session-transcript-reconcile-write-contract.js";
import { createSessionTranscriptReconcileWriter } from "./session-transcript-reconcile-writer.js";

type EntryWorkerArgs = Parameters<typeof withSessionEntryWorker>;
const adapter = vi.hoisted(() => ({
  run: vi.fn<(...args: EntryWorkerArgs) => Promise<unknown>>(),
}));
vi.mock("./session-accessor.sqlite-replacement-worker.js", () => ({
  withSessionEntryWorker: adapter.run,
}));
afterEach(() => vi.restoreAllMocks());

const plan = {
  sessionId: "settlement",
  activeEventCount: 1,
  activeMessageCount: 1,
  leafEventId: "leaf",
  sourceHasInvalidLeafControl: false,
  sourceIndexedSeq: 1,
  sourceTranscriptGeneration: "original-generation",
  sourceTranscriptUpdatedAt: 1,
};
const finalize: SessionTranscriptReconcileWrite & { kind: "finalize" } = {
  kind: "finalize",
  claimId: 3,
  plan,
};
const committedFinalize = {
  kind: "finalize",
  finalized: true,
  sessionKey: "agent:main:settlement",
} satisfies SessionTranscriptReconcileWriteResult;

/** The adapter boundary supplies trusted private receipts; this fixture grants no native access. */
function fixture(onTestFinished: (cleanup: () => void) => void) {
  const options = { agentId: "main", path: "/synthetic/reconcile.sqlite", env: {} };
  const order: string[] = [];
  const admission = createSqliteWorkerOperationAdmission(() => {
    throw new Error("No native admission is available in this receipt fixture");
  });
  onTestFinished(() => admission.finish());
  const settled = createDeferredCore<SqliteWorkerOperationSettlement>();
  const state: {
    held: boolean;
    missing: boolean;
    granted: boolean;
    autoSettle: boolean;
    publication: unknown;
    committed: { facts: unknown } | undefined;
    settlement: SqliteWorkerNativeSettlement | undefined;
    deliveryError?: unknown;
    cleanupError?: unknown;
  } = {
    held: false,
    missing: false,
    granted: true,
    autoSettle: true,
    publication: { kind: "session-transcript-index-write", result: committedFinalize },
    committed: {
      facts: { kind: "session-transcript-index-write", result: committedFinalize },
    },
    settlement: { kind: "completed" },
  };
  vi.spyOn(admission, "committed", "get").mockImplementation(() => state.committed);
  vi.spyOn(admission, "settlement", "get").mockImplementation(() => state.settlement);
  const worker: AgentDatabaseExecutionScope = {
    async execute() {
      throw new Error("Fixture execution was not prepared");
    },
  };
  const execute = vi.spyOn(worker, "execute");
  const prepare = vi.fn<OpenClawAgentDatabaseExecution["prepare"]>().mockResolvedValue(undefined);
  const source: AgentDatabaseRequestExecutionSource = {
    assertCurrent() {},
    createAdmission() {
      throw new Error("Fixture does not create native admissions");
    },
  };
  const execution: OpenClawAgentDatabaseExecution = {
    agentId: options.agentId,
    path: options.path,
    fileIdentity: {
      kind: "file",
      physicalIdentity: "1:2",
      nativeLocation: options.path,
      birthtime: "3",
    },
    assertCurrent() {},
    prepare,
    async runExisting(_source, run) {
      if (state.missing) {
        return undefined;
      }
      return await run(worker);
    },
    async release() {},
  };
  const context: SessionEntryCommitContext = { env: options.env, assertCurrent() {} };
  adapter.run
    .mockReset()
    .mockImplementation(
      async (_options, identity, assertCurrent, run, onCommit, retainedExecution) => {
        expect(retainedExecution).toBe(execution);
        expect(identity).toBe("1:2");
        assertCurrent();
        state.held = true;
        order.push("fifo-entered");
        execute.mockImplementation(async (command) => {
          expect(state.held).toBe(true);
          expect(command.type).toBe("session.transcriptIndex.write");
          if (state.granted) {
            onCommit?.(admission, { settled: settled.promise }, { publication: state.publication });
          }
          order.push("delivery");
          if (state.autoSettle) {
            settled.resolve({ kind: "completed" });
          }
          if (state.deliveryError) {
            throw state.deliveryError;
          }
          // Delivery is not authoritative; the adapter must select the private commit receipt.
          return undefined;
        });
        try {
          const result = await run(execution, source, context);
          if (state.cleanupError) {
            throw state.cleanupError;
          }
          return result;
        } finally {
          state.held = false;
          order.push("fifo-released");
        }
      },
    );
  const published: unknown[] = [];
  const publicationCustody: boolean[] = [];
  const stop = sessionChanges.subscribe((change) => {
    published.push(change);
    publicationCustody.push(state.held);
    order.push("published");
  });
  onTestFinished(stop);
  return {
    state,
    order,
    settled,
    published,
    publicationCustody,
    execute,
    prepare,
    writer: createSessionTranscriptReconcileWriter(options, execution, () => {}),
  };
}

it("publishes a confirmed finalize commit inside FIFO after a lost reply and joins settlement", async ({
  onTestFinished,
}) => {
  const owned = fixture(onTestFinished);
  const deliveryFailure = new Error("Finalize reply lost after commit");
  owned.state.deliveryError = deliveryFailure;
  owned.state.autoSettle = false;
  const writing = owned.writer.write(finalize);
  const failure = writing.catch((error: unknown) => error);
  expect(owned.order).toEqual(["fifo-entered", "delivery"]);
  expect(owned.published).toEqual([]);
  owned.settled.resolve({ kind: "unknown", error: deliveryFailure });
  await expect(failure).resolves.toBe(deliveryFailure);
  expect(owned.published).toEqual([
    { storePath: "/synthetic/reconcile.sqlite", sessionKey: "agent:main:settlement" },
  ]);
  expect(owned.order).toEqual(["fifo-entered", "delivery", "published", "fifo-released"]);
  expect(owned.publicationCustody).toEqual([true]);
  expect(owned.execute).toHaveBeenCalledOnce();
});

it("publishes a confirmed commit before propagating adapter cleanup failure", async ({
  onTestFinished,
}) => {
  const owned = fixture(onTestFinished);
  const cleanupFailure = new Error("Committed phase cleanup failed");
  owned.state.cleanupError = cleanupFailure;
  await expect(owned.writer.write(finalize)).rejects.toBe(cleanupFailure);
  expect(owned.published).toHaveLength(1);
  expect(owned.publicationCustody).toEqual([true]);
  expect(owned.order).toEqual(["fifo-entered", "delivery", "published", "fifo-released"]);
});

it("propagates a confirmed rollback without publishing or replaying", async ({
  onTestFinished,
}) => {
  const owned = fixture(onTestFinished);
  const rollback = new Error("Finalize transaction rolled back");
  owned.state.committed = undefined;
  owned.state.deliveryError = rollback;
  await expect(owned.writer.write(finalize)).rejects.toBe(rollback);
  expect(owned.published).toEqual([]);
  expect(owned.execute).toHaveBeenCalledOnce();
});

it.for(["unknown native completion", "missing commit receipt", "missing final admission"])(
  "fences %s without publishing a plausible delivery",
  async (fault, { onTestFinished }) => {
    const owned = fixture(onTestFinished);
    if (fault === "unknown native completion") {
      owned.state.settlement = { kind: "unknown" };
    } else if (fault === "missing commit receipt") {
      owned.state.committed = undefined;
    } else {
      owned.state.granted = false;
    }
    const error: unknown = await owned.writer.write(finalize).catch((failure: unknown) => failure);
    expect(hasSqliteWorkerOutcomeUnknown(error)).toBe(true);
    expect(owned.published).toEqual([]);
    expect(owned.execute).toHaveBeenCalledOnce();
  },
);

it("rejects the wrong phase at final admission and at native receipt consumption", async ({
  onTestFinished,
}) => {
  const owned = fixture(onTestFinished);
  owned.state.publication = {
    kind: "session-transcript-index-write",
    result: { kind: "claim", owned: true },
  };
  await expect(owned.writer.write(finalize)).rejects.toThrow("omitted its phase receipt");
  expect(owned.published).toEqual([]);
  owned.state.publication = { kind: "session-transcript-index-write", result: committedFinalize };
  owned.state.committed = {
    facts: { kind: "session-transcript-index-write", result: { kind: "claim", owned: true } },
  };
  const failure: unknown = await owned.writer.write(finalize).catch((error: unknown) => error);
  expect(hasSqliteWorkerOutcomeUnknown(failure)).toBe(true);
  expect(owned.published).toEqual([]);
});

it("preserves refused claims and void phase wrappers while refusing missing storage", async ({
  onTestFinished,
}) => {
  const owned = fixture(onTestFinished);
  const refused = { kind: "claim", owned: false } satisfies SessionTranscriptReconcileWriteResult;
  owned.state.publication = { kind: "session-transcript-index-write", result: refused };
  owned.state.committed = { facts: owned.state.publication };
  await expect(owned.writer.write({ kind: "claim", plan, claimId: 3 })).resolves.toEqual(refused);
  const sweep = { kind: "orphan-sweep" } satisfies SessionTranscriptReconcileWriteResult;
  owned.state.publication = { kind: "session-transcript-index-write", result: sweep };
  owned.state.committed = { facts: owned.state.publication };
  await expect(owned.writer.write({ kind: "orphan-sweep" })).resolves.toEqual(sweep);
  owned.state.missing = true;
  await expect(owned.writer.write({ kind: "orphan-sweep" })).rejects.toThrow(
    "lost its retained database",
  );
  expect(owned.execute).toHaveBeenCalledTimes(2);
  expect(owned.published).toEqual([]);
});

it("prepares first-use storage only for preflight and returns confirmed no-work", async ({
  onTestFinished,
}) => {
  const owned = fixture(onTestFinished);
  const result = {
    kind: "preflight",
    hasWork: false,
  } satisfies SessionTranscriptReconcileWriteResult;
  owned.state.publication = { kind: "session-transcript-index-write", result };
  owned.state.committed = { facts: owned.state.publication };
  await expect(owned.writer.write({ kind: "preflight" })).resolves.toEqual(result);
  expect(owned.prepare).toHaveBeenCalledOnce();
  expect(owned.published).toEqual([]);
});
