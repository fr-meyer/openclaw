import type { DatabaseSync } from "node:sqlite";
import {
  assertTransactionUsable,
  type SqliteWorkerBackend,
} from "openclaw/plugin-sdk/sqlite-worker-runtime";
import { createBoundedMemoryEscrow } from "./bounded-admission-escrow.js";
import { readBoundedMemoryRequirement } from "./bounded-admission-required.js";
import type {
  BoundedWorkerBinding,
  BoundedWorkerOperations,
} from "./bounded-admission-worker-task.js";

// Supplied canonical native owner connection only; never opens an independent DB.
export function bindSqliteWorkerBackend(
  input: BoundedWorkerBinding,
  context: { database: DatabaseSync; admit(stage: "transaction" | "commit"): void },
) {
  const db = context.database;
  let escrow: ReturnType<typeof createBoundedMemoryEscrow> | undefined;
  let operation: string | undefined;
  let closed = false;
  return {
    execute(command) {
      if (closed) {
        throw new Error("Bounded worker closed");
      }
      if (command.type === "required") {
        if (command.input.agentId !== input.agentId) {
          throw new Error("Agent binding mismatch");
        }
        return readBoundedMemoryRequirement(db, input.agentId);
      }
      if (command.type === "initialize") {
        if (escrow || command.input.policy.agent !== input.agentId) {
          throw new Error("Worker policy binding mismatch");
        }
        escrow = createBoundedMemoryEscrow(db, command.input.policy, command.input.allocation, {
          begin: () => context.admit("transaction"),
          commit: () => context.admit("commit"),
        });
        operation = command.input.policy.operation;
        return escrow.receipt(operation);
      }
      if (!escrow || command.input.operation !== operation) {
        throw new Error("Worker operation binding mismatch");
      }
      if (command.type === "debit") {
        escrow.debit(
          operation,
          command.input.phase,
          command.input.root,
          command.input.need,
          Date.now(),
        );
      } else if (command.type === "stop") {
        escrow.stop(operation);
      } else if (command.type === "recovery") {
        escrow.recovery();
      } else if (command.type === "resume") {
        escrow.resumeOrdinary(operation);
      }
      return escrow.receipt(operation);
    },
    assertSettled() {
      assertTransactionUsable(db);
      if (!db.isOpen || db.isTransaction) {
        throw new Error("Unsettled bounded escrow transaction");
      }
    },
    close() {
      closed = true;
    },
  } satisfies SqliteWorkerBackend<BoundedWorkerOperations>;
}
