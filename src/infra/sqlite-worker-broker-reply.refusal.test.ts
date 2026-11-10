import { expect, it, vi } from "vitest";
import { createDeferredCore } from "../shared/deferred.js";
import {
  receiveSqliteWorkerReply,
  settleFailedSqliteWorkerJobs,
  settleSqliteWorkerJob,
} from "./sqlite-worker-broker-reply.js";
import type { Job } from "./sqlite-worker-broker.types.js";
import { SqliteWorkerError } from "./sqlite-worker-contract.js";
import {
  bindSqliteWorkerOpenRefusal,
  getSqliteWorkerOpenRefusalProof,
} from "./sqlite-worker-open-refusal.js";
import { createSqliteWorkerOperationAdmission } from "./sqlite-worker-operation-admission.js";

it.each([
  "verified",
  "missing",
  "delayed",
  "wrong id",
  "wrong actor",
  "duplicate",
  "commit",
  "completed settlement",
  "unknown settlement",
  "protocol",
  "authority then protocol",
  "service failure",
  "cleanup",
  "finish failure",
  "release failure",
  "retire",
  "both flags",
  "unbound",
  "missing outcome",
  "missing refusal",
  "execute",
  "success with marker",
  "legacy with marker",
  "ordinary with marker",
] as const)("requires complete, clean first-guard refusal proof (%s)", async (proof) => {
  const refusal = new Error("Original opening authority refused");
  const cleanup = new Error("Opening admission cleanup failed");
  const admission = createSqliteWorkerOperationAdmission(() => {
    throw refusal;
  });
  const finishAdmission = admission.finish.bind(admission);
  if (proof !== "unbound" && proof !== "execute") {
    bindSqliteWorkerOpenRefusal(admission, { id: 1, actor: 1 });
  }
  admission.bindDatabaseAuthority({
    databasePath: "/synthetic/state.sqlite",
    assertAccess() {},
    assertRequest() {
      if (proof === "authority then protocol") {
        throw refusal;
      }
    },
    acquireSchema: () => ({
      assertCurrent() {},
      release: () => {
        throw cleanup;
      },
    }),
  });
  const post = (message: unknown) => admission.port.postMessage(message, []);
  if (proof === "cleanup") {
    post({
      stage: "prepare",
      facts: { kind: "schema-maintenance", databasePath: "/synthetic/state.sqlite" },
      decision: new SharedArrayBuffer(4),
    });
    admission.service();
  }
  post({ stage: "open", facts: undefined, decision: new SharedArrayBuffer(4) });
  admission.service();
  expect(admission.failure).toBe(refusal);
  if (proof === "commit") {
    post({
      kind: "native-commit",
      committed: { version: 1, operationId: "synthetic", sequence: 1, facts: { rows: 1 } },
    });
  } else if (proof.endsWith("settlement")) {
    post({
      kind: "native-settlement",
      settlement: { kind: proof === "unknown settlement" ? "unknown" : "completed" },
    });
  } else if (proof === "protocol" || proof === "authority then protocol") {
    post({ kind: "native-settlement", settlement: { kind: "invalid" } });
  }
  const marker = {
    kind: "native-open-not-entered",
    id: proof === "wrong id" ? 2 : 1,
    actor: proof === "wrong actor" ? 2 : 1,
  };
  if (proof !== "missing" && proof !== "delayed") {
    post(marker);
    if (proof === "duplicate") {
      post(marker);
    }
  }
  const service = vi.spyOn(admission, "service");
  if (proof === "service failure") {
    service.mockImplementation(() => {
      throw cleanup;
    });
  }
  const finish = vi.spyOn(admission, "finish");
  if (proof === "finish failure") {
    finish.mockImplementation(() => {
      throw cleanup;
    });
  }
  const release = vi.fn(() => {
    if (proof === "release failure") {
      throw cleanup;
    }
  });
  const retired = createDeferredCore();
  const resolve = vi.fn();
  const reject = vi.fn();
  const settleNative = vi.fn();
  const job: Job = {
    observation: { started() {}, completed() {} },
    request:
      proof === "execute"
        ? { type: "execute", id: 1, actor: 1, input: new Uint8Array() }
        : {
            type: "open",
            id: 1,
            actor: 1,
            moduleUrl: "file:///synthetic/backend.js",
            databasePath: "/synthetic/agent.sqlite",
            input: new Uint8Array(),
          },
    bytes: 0,
    nativeDispatched: true,
    dispatchState: { dispatched: true },
    operationAdmission: { admission, releaseService: release },
    resolve,
    reject,
    settleNative,
    detach() {},
  };
  const dispatch = vi.fn();
  const fail = vi.fn((error: unknown, currentError?: Error) => {
    settleFailedSqliteWorkerJobs({
      current: job,
      queued: [],
      queuedError: new SqliteWorkerError("retired", "unavailable"),
      error: error instanceof Error ? error : new Error(String(error)),
      currentError,
      retire: () => retired.promise,
      finish: settleSqliteWorkerJob,
    });
  });
  try {
    receiveSqliteWorkerReply(
      { actors: new Set(), current: job, worker: { postMessage() {} } },
      proof === "success with marker"
        ? { id: 1, ok: true, value: new Uint8Array() }
        : {
            id: 1,
            ok: false,
            ...(proof === "legacy with marker" || proof === "ordinary with marker"
              ? {}
              : { preNativeOpenRefusal: true as const }),
            ...(proof === "missing outcome"
              ? {}
              : { openOutcome: "refused-before-agent-open" as const }),
            ...(proof === "missing refusal" ? {} : { admissionRefused: true as const }),
            ...(proof === "retire" ? { retire: true as const } : {}),
            ...(proof === "both flags" || proof === "legacy with marker"
              ? { openNotEntered: true as const }
              : {}),
            error: { name: "Error", message: refusal.message },
          },
      { fail, finish: settleSqliteWorkerJob, dispatch },
    );
    if (proof === "delayed") {
      post(marker);
    }
    const finalizedEarly = ["verified", "cleanup", "finish failure", "release failure"].includes(
      proof,
    );
    expect(finish).toHaveBeenCalledTimes(finalizedEarly ? 1 : 0);
    expect(release).toHaveBeenCalledTimes(finalizedEarly ? 1 : 0);
    if (proof === "verified") {
      expect(fail).not.toHaveBeenCalled();
      expect(job.dispatchState?.openNotEntered).toBe(true);
      expect(reject).toHaveBeenCalledExactlyOnceWith(refusal);
      expect(settleNative).toHaveBeenCalledExactlyOnceWith({ kind: "not-entered", error: refusal });
      expect(dispatch).toHaveBeenCalledOnce();
    } else {
      expect(fail).toHaveBeenCalledOnce();
      expect(job.dispatchState?.openNotEntered).toBeUndefined();
      expect(settleNative).not.toHaveBeenCalled();
      expect(reject).not.toHaveBeenCalled();
      expect(dispatch).not.toHaveBeenCalled();
      retired.resolve();
      await retired.promise;
      expect(settleNative).toHaveBeenCalledWith(
        expect.objectContaining({
          kind: "unknown",
          ...(proof === "cleanup" ? {} : { nativeStopped: true }),
        }),
      );
      expect(reject).toHaveBeenCalledOnce();
      expect(finish).toHaveBeenCalledOnce();
      expect(release).toHaveBeenCalledOnce();
    }
    expect(resolve).not.toHaveBeenCalled();
    if (
      [
        "protocol",
        "authority then protocol",
        "duplicate",
        "commit",
        "completed settlement",
        "unknown settlement",
        "wrong id",
        "wrong actor",
        "unbound",
        "execute",
      ].includes(proof)
    ) {
      expect(getSqliteWorkerOpenRefusalProof(admission)?.protocolFailure).toBeDefined();
    }
  } finally {
    retired.resolve();
    service.mockRestore();
    finish.mockRestore();
    finishAdmission();
  }
});
