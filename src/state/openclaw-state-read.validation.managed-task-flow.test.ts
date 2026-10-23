import { describe, expect, it } from "vitest";
import { isReadRequest } from "./openclaw-state-read.validation.js";

const ownerKey = "agent:main:publisher";
const otherOwnerKey = "agent:main:legacy";
const controllerId = "mergeguez-pr-lifecycle/v1";

function request(command: unknown) {
  return {
    databasePath: "/tmp/managed-task-flow-validation.sqlite",
    location: "/tmp/managed-task-flow-validation.sqlite",
    checkFreshAdmission: false,
    context: { environment: { OPENCLAW_STATE_DIR: "/tmp" } },
    command,
  };
}

describe("managed TaskFlow read worker admission", () => {
  it("accepts bounded canonical controller observations", () => {
    expect(
      isReadRequest(
        request({
          type: "tasks.managedFlows.capacitySnapshot",
          input: { ownerKey, controllerId, ownerSessionKeys: [ownerKey, otherOwnerKey] },
        }),
      ),
    ).toBe(true);
    expect(
      isReadRequest(
        request({
          type: "tasks.runs.get",
          input: { ownerKey, controllerId, taskId: "task-1", legacyOwnerObservation: false },
        }),
      ),
    ).toBe(true);
  });

  it.each([
    { type: "tasks.managedFlows.capacitySnapshot", input: { ownerKey, controllerId } },
    {
      type: "tasks.managedFlows.capacitySnapshot",
      input: { ownerKey, controllerId, ownerSessionKeys: [otherOwnerKey] },
    },
    {
      type: "tasks.managedFlows.capacitySnapshot",
      input: { ownerKey, controllerId, ownerSessionKeys: [ownerKey, ownerKey] },
    },
    {
      type: "tasks.managedFlows.capacitySnapshot",
      input: {
        ownerKey,
        controllerId,
        ownerSessionKeys: [
          ownerKey,
          ...Array.from({ length: 64 }, (_, index) => `agent:main:owner-${index}`),
        ],
      },
    },
    { type: "tasks.managedFlows.get", input: { ownerKey, controllerId } },
    { type: "tasks.runs.get", input: { ownerKey, controllerId, taskId: "task-1" } },
    {
      type: "tasks.runs.list",
      input: { ownerKey, controllerId, legacyOwnerObservation: "yes" },
    },
  ])("rejects malformed $type input at the worker boundary", (command) => {
    expect(isReadRequest(request(command))).toBe(false);
  });
});
