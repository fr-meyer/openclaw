import { describe, expect, it, vi } from "vitest";
import { createManagedTaskFlowHost } from "./managed-task-flow-host.js";

function createBoundHost() {
  let current = true;
  const execute = vi.fn(async () => {
    throw new Error("unexpected shared-state command");
  });
  const host = createManagedTaskFlowHost({
    assertCurrent: () => {
      if (!current) {
        throw new Error("controller retired");
      }
    },
    bindSessionAuthority: ({ sessionKey }) => ({
      ownerKey: sessionKey,
      controllerId: "publisher/v1",
      legacyOwnerObservation: false,
      assertCurrent: () => {
        if (!current) {
          throw new Error("controller retired");
        }
      },
      assertOwnerSelection: (ownerSessionKeys) => {
        if (ownerSessionKeys.some((key) => key !== sessionKey)) {
          throw new Error("foreign session owner");
        }
      },
    }),
    execute,
    cancel: async () => {
      throw new Error("unexpected cancellation");
    },
  });
  return { host, execute, retire: () => (current = false) };
}

describe("managed TaskFlow host admission", () => {
  it("rejects a different controller and foreign capacity owners before a worker command", async () => {
    const { host, execute } = createBoundHost();
    const flows = host.managedFlows.bindSession({ sessionKey: "agent:main:publisher" });
    await expect(
      flows.createManaged({ controllerId: "foreign/v1", goal: "publish" }),
    ).rejects.toThrow(/controller differs/u);
    expect(() => flows.capacitySnapshot({ ownerSessionKeys: ["agent:main:foreign"] })).toThrow(
      /foreign session owner/u,
    );
    expect(execute).not.toHaveBeenCalled();
  });

  it("rechecks controller authority at asynchronous command dispatch", async () => {
    const { host, execute, retire } = createBoundHost();
    const flows = host.managedFlows.bindSession({ sessionKey: "agent:main:publisher" });
    const pending = flows.list();
    retire();
    await expect(pending).rejects.toThrow(/controller retired/u);
    expect(execute).not.toHaveBeenCalled();
  });

  it("revokes bound access synchronously on close", async () => {
    const { host, execute } = createBoundHost();
    const runs = host.runs.bindSession({ sessionKey: "agent:main:publisher" });
    const closed = host.close();
    await expect(runs.list()).rejects.toThrow(/host is closed/u);
    await closed;
    expect(execute).not.toHaveBeenCalled();
  });
});
