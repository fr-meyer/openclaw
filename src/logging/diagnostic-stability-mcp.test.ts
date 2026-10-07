import fs from "node:fs";
import { afterEach, beforeEach, expect, it } from "vitest";
import { useAutoCleanupTempDirTracker } from "../../test/helpers/temp-dir.js";
import {
  emitDiagnosticEvent,
  emitTrustedDiagnosticEvent,
  resetDiagnosticEventsForTest,
  waitForDiagnosticEventsDrained,
} from "../infra/diagnostic-events.js";
import type { DiagnosticMcpLifecycleFields } from "../infra/diagnostic-mcp-lifecycle.js";
import {
  readDiagnosticStabilityBundleFileSync,
  writeDiagnosticStabilityBundleSync,
} from "./diagnostic-stability-bundle.js";
import {
  getDiagnosticStabilitySnapshot,
  resetDiagnosticStabilityRecorderForTest,
  startDiagnosticStabilityRecorder,
  stopDiagnosticStabilityRecorder,
} from "./diagnostic-stability.js";

const tempDirs = useAutoCleanupTempDirTracker(afterEach);
const mcp: DiagnosticMcpLifecycleFields = {
  generationId: "11111111-1111-4111-8111-111111111111",
  providerClass: "stdio",
  childPid: 1234,
  serverRuntimeActiveLeases: 2,
  retirementIntent: "required",
  retiring: true,
  connected: false,
  closeOutcome: "pending",
};

beforeEach(() => {
  resetDiagnosticStabilityRecorderForTest();
  resetDiagnosticEventsForTest();
  startDiagnosticStabilityRecorder();
});
afterEach(() => {
  stopDiagnosticStabilityRecorder();
  resetDiagnosticStabilityRecorderForTest();
  resetDiagnosticEventsForTest();
});

it("rejects spoofed ownership and preserves only closed metadata in ring and bundle reads", async () => {
  emitDiagnosticEvent({ type: "mcp.lifecycle", phase: "cleanup", mcp });
  emitTrustedDiagnosticEvent({
    type: "mcp.lifecycle",
    phase: "retirement",
    mcp: Object.assign({}, mcp, {
      serverName: "synthetic-private-alias",
      url: "https://synthetic.invalid/private",
      args: ["synthetic-private-argument"],
      env: { TOKEN: "synthetic-private-token" },
      error: "synthetic-private-error",
    }),
  });
  await waitForDiagnosticEventsDrained();
  const snapshot = getDiagnosticStabilitySnapshot({ type: "mcp.lifecycle" });
  expect(snapshot.count).toBe(1);
  expect(snapshot.events[0]?.mcp).toEqual(mcp);
  expect(JSON.stringify(snapshot)).not.toContain("synthetic-private");
  const written = writeDiagnosticStabilityBundleSync({
    reason: "gateway.startup_failed",
    stateDir: tempDirs.make("openclaw-mcp-diagnostics-"),
  });
  expect(written.status).toBe("written");
  if (written.status !== "written") {
    throw new Error("Expected diagnostic bundle");
  }
  const read = readDiagnosticStabilityBundleFileSync(written.path);
  expect(read.status).toBe("found");
  if (read.status !== "found") {
    throw new Error("Expected readable diagnostic bundle");
  }
  expect(read.bundle.snapshot.events[0]?.mcp).toEqual(mcp);
  // A bundle is untrusted input too: closed phase values cannot become secret text.
  const forged = structuredClone(read.bundle);
  forged.snapshot.events[0]!.phase = "synthetic-private-token";
  fs.writeFileSync(written.path, JSON.stringify(forged));
  expect(readDiagnosticStabilityBundleFileSync(written.path).status).toBe("failed");
});

it.each([
  ["generationId", "synthetic-private-session"],
  ["providerClass", "synthetic-private-url"],
  ["childPid", -1],
  ["serverRuntimeActiveLeases", Number.POSITIVE_INFINITY],
  ["retirementIntent", "synthetic-private-reason"],
  ["closeOutcome", "synthetic-private-error"],
  ["connected", "synthetic-private-token"],
])("omits malformed ownership fields (%s)", async (key, value) => {
  const malformed = { ...mcp };
  Reflect.set(malformed, key, value);
  emitTrustedDiagnosticEvent({ type: "mcp.lifecycle", phase: "cleanup", mcp: malformed });
  await waitForDiagnosticEventsDrained();
  const record = getDiagnosticStabilitySnapshot({ type: "mcp.lifecycle" }).events[0];
  expect(record?.mcp).toBeUndefined();
  expect(JSON.stringify(record)).not.toContain("synthetic-private");
});

it("keeps lifecycle output within the existing ring and query bounds with visible eviction", async () => {
  const capacity = getDiagnosticStabilitySnapshot().capacity;
  for (let index = 0; index <= capacity; index++) {
    emitTrustedDiagnosticEvent({
      type: "mcp.lifecycle",
      phase: "lease",
      mcp: { ...mcp, serverRuntimeActiveLeases: index },
    });
  }
  await waitForDiagnosticEventsDrained();
  const bounded = getDiagnosticStabilitySnapshot({ type: "mcp.lifecycle", limit: 3 });
  expect(bounded.count).toBe(capacity);
  expect(bounded.dropped).toBe(1);
  expect(bounded.events.map((record) => record.mcp?.serverRuntimeActiveLeases)).toEqual([
    capacity - 2,
    capacity - 1,
    capacity,
  ]);
  expect(() =>
    getDiagnosticStabilitySnapshot({ type: "mcp.lifecycle", limit: Number.MAX_SAFE_INTEGER }),
  ).toThrow("limit must be between 1 and 1000");
  expect(JSON.stringify(bounded.events).length).toBeLessThan(2000);
});
