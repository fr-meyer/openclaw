import { describe, expect, it, vi } from "vitest";
import { createManagedTaskFlowHost } from "./managed-task-flow-host.js";

function createBoundHost(authorityOverrides: Record<string, unknown> = {}) {
  let current = true;
  const execute = vi.fn(async (_command: unknown) => {
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
      ...authorityOverrides,
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
    expect(() =>
      flows.capacitySnapshot({
        ownerSessionKeys: ["agent:main:publisher", "agent:main:foreign"],
      }),
    ).toThrow(/foreign session owner/u);
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

  it.each([
    { ownerKey: " agent:main:publisher" },
    { ownerKey: "not-a-session-key" },
    { ownerKey: "agent:main:subagent:incognito-private" },
    { controllerId: " publisher/v1" },
    { controllerId: " " },
    { legacyOwnerObservation: "yes" },
    { legacyOwnerObservation: undefined },
  ])("rejects noncanonical admitted binding facts before dispatch: %j", (overrides) => {
    const { host, execute } = createBoundHost(overrides);
    expect(() => host.managedFlows.bindSession({ sessionKey: "agent:main:publisher" })).toThrow();
    expect(execute).not.toHaveBeenCalled();
  });

  it.each(
    [
      undefined,
      [],
      ["agent:main:foreign"],
      ["agent:main:publisher", "agent:main:publisher"],
      ["agent:main:publisher", " agent:main:foreign"],
      ["agent:main:publisher", "not-a-session-key"],
      ["agent:main:publisher", "agent:main:subagent:incognito-private"],
      ["agent:main:publisher", ...Array.from({ length: 64 }, (_, i) => `agent:main:owner-${i}`)],
    ].map((ownerSessionKeys) => ({ ownerSessionKeys })),
  )("rejects a malformed capacity selection before transport: %j", ({ ownerSessionKeys }) => {
    const { host, execute } = createBoundHost();
    const flows = host.managedFlows.bindSession({ sessionKey: "agent:main:publisher" });
    // Exercise malformed JavaScript/plugin input at the public method, without
    // inventing a second untyped transport or retaining the removed worker guard.
    expect(() => Reflect.apply(flows.capacitySnapshot, flows, [{ ownerSessionKeys }])).toThrow();
    expect(execute).not.toHaveBeenCalled();
  });

  it.each([undefined, null, "", " ", 42])(
    "rejects empty or non-string lookup identities before dispatch: %j",
    async (id) => {
      const { host, execute } = createBoundHost();
      const flows = host.managedFlows.bindSession({ sessionKey: "agent:main:publisher" });
      const runs = host.runs.bindSession({ sessionKey: "agent:main:publisher" });
      await expect(Reflect.apply(flows.get, flows, [id])).rejects.toThrow(/identity/u);
      await expect(Reflect.apply(runs.get, runs, [id])).rejects.toThrow(/identity/u);
      expect(execute).not.toHaveBeenCalled();
    },
  );

  it("dispatches canonical bounded observations with the admitted policy", async () => {
    const { host, execute } = createBoundHost();
    // A deliberate transport refusal proves these arguments reached the real
    // dispatch point; negative cases above must never reach that point.
    const flows = host.managedFlows.bindSession({ sessionKey: "agent:main:publisher" });
    const runs = host.runs.bindSession({ sessionKey: "agent:main:publisher" });
    await expect(
      flows.capacitySnapshot({ ownerSessionKeys: ["agent:main:publisher"] }),
    ).rejects.toThrow(/unexpected shared-state command/u);
    await expect(flows.get("flow-1")).rejects.toThrow(/unexpected shared-state command/u);
    await expect(runs.get("task-1")).rejects.toThrow(/unexpected shared-state command/u);
    expect(execute.mock.calls.map(([command]) => command)).toEqual([
      {
        type: "tasks.managedFlows.capacitySnapshot",
        input: {
          ownerKey: "agent:main:publisher",
          controllerId: "publisher/v1",
          ownerSessionKeys: ["agent:main:publisher"],
        },
      },
      {
        type: "tasks.managedFlows.get",
        input: {
          ownerKey: "agent:main:publisher",
          controllerId: "publisher/v1",
          flowId: "flow-1",
        },
      },
      {
        type: "tasks.runs.get",
        input: {
          ownerKey: "agent:main:publisher",
          controllerId: "publisher/v1",
          taskId: "task-1",
          legacyOwnerObservation: false,
        },
      },
    ]);
  });
});
