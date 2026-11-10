import { isRecord } from "@openclaw/normalization-core/record-coerce";
import { resolveGlobalSingleton } from "../shared/global-singleton.js";
import type { SqliteWorkerOperationAdmission } from "./sqlite-worker-operation-admission.js";

type OpenRefusalReceipt = Readonly<{ id: number; actor: number }>;

/** Each private admission starts unbound; only host OPEN dispatch can bind it. */
export function createSqliteWorkerOpenRefusalProof() {
  let expected: OpenRefusalReceipt | undefined;
  let receipt: OpenRefusalReceipt | undefined;
  let observed = false;
  let protocolFailure: unknown;
  return {
    bind(request: OpenRefusalReceipt) {
      if (expected) {
        throw new Error("SQLite open refusal proof is already bound");
      }
      expected = { ...request };
    },
    recordProtocolFailure(error: unknown) {
      protocolFailure ??= error;
    },
    get protocolFailure() {
      return protocolFailure;
    },
    get receipt() {
      return receipt;
    },
    get observed() {
      return observed;
    },
    accept(message: unknown, hasNativeReceipt: boolean): boolean {
      observed = true;
      if (
        receipt ||
        !expected ||
        hasNativeReceipt ||
        !isRecord(message) ||
        message.kind !== "native-open-not-entered" ||
        message.id !== expected.id ||
        message.actor !== expected.actor
      ) {
        return false;
      }
      receipt = { ...expected };
      return true;
    },
  };
}

const openRefusalBindings = resolveGlobalSingleton(
  Symbol.for("openclaw.sqliteWorkerOpenRefusalBindings"),
  () =>
    new WeakMap<
      SqliteWorkerOperationAdmission,
      ReturnType<typeof createSqliteWorkerOpenRefusalProof>
    >(),
);

export function registerSqliteWorkerOpenRefusalProof(
  admission: SqliteWorkerOperationAdmission,
  proof: ReturnType<typeof createSqliteWorkerOpenRefusalProof>,
): void {
  openRefusalBindings.set(admission, proof);
}

/** Private host binding leaves released admission factories structurally unchanged. */
export function bindSqliteWorkerOpenRefusal(
  admission: SqliteWorkerOperationAdmission,
  request: OpenRefusalReceipt,
): void {
  openRefusalBindings.get(admission)?.bind(request);
}

export function hasSqliteWorkerOpenRefusalReceipt(
  admission: SqliteWorkerOperationAdmission,
): boolean {
  return openRefusalBindings.get(admission)?.observed ?? false;
}

export function getSqliteWorkerOpenRefusalProof(admission: SqliteWorkerOperationAdmission) {
  const proof = openRefusalBindings.get(admission);
  return proof
    ? { receipt: proof.receipt, observed: proof.observed, protocolFailure: proof.protocolFailure }
    : undefined;
}

/** Refusal provenance alone does not certify that no native handle was acquired. */
export const SqliteWorkerOpenRefusedError = resolveGlobalSingleton(
  Symbol.for("openclaw.sqliteWorkerOpenRefusedError"),
  () =>
    class OpenRefusedError extends Error {
      constructor(readonly originalError: unknown) {
        super("SQLite worker admission was refused before agent open", { cause: originalError });
        this.name = "SqliteWorkerOpenRefusedError";
      }
    },
);

const preNativeOpenRefusals = resolveGlobalSingleton(
  Symbol.for("openclaw.sqliteWorkerPreNativeOpenRefusals"),
  () => new WeakSet<Error>(),
);

/** The first built-in factory guard runs before shared or native acquisition. */
export function createSqliteWorkerPreNativeOpenRefusal(originalError: unknown) {
  const refusal = new SqliteWorkerOpenRefusedError(originalError);
  preNativeOpenRefusals.add(refusal);
  return refusal;
}

export function isSqliteWorkerPreNativeOpenRefusal(
  error: unknown,
): error is InstanceType<typeof SqliteWorkerOpenRefusedError> {
  return error instanceof SqliteWorkerOpenRefusedError && preNativeOpenRefusals.has(error);
}
