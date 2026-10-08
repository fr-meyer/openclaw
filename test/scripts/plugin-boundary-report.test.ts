// Plugin Boundary Report tests cover plugin boundary report script behavior.
import { beforeAll, describe, expect, it, vi } from "vitest";
import {
  createPluginBoundaryReport,
  isPluginCompatEligibleForRemoval,
  type PluginBoundaryReportResult,
} from "../../scripts/plugin-boundary-report.js";
import * as pluginCompatRegistry from "../../src/plugins/compat/registry.js";

describe("plugin-boundary-report", () => {
  let summaryResult: PluginBoundaryReportResult;

  beforeAll(() => {
    summaryResult = createPluginBoundaryReport(["--summary", "--json"]);
  });

  it("emits compact CI-safe summary JSON", () => {
    const summary = JSON.parse(summaryResult.stdout) as {
      compat?: {
        removalPendingCount?: unknown;
        removalPendingDueCount?: unknown;
        removalPending?: Array<{
          code?: unknown;
          removeAfter?: unknown;
          blocker?: unknown;
          readerCount?: unknown;
          readerSample?: unknown;
          dueForReview?: unknown;
        }>;
      };
      memoryHostSdk?: {
        implementation?: unknown;
      };
    };

    expect(summaryResult.exitCode).toBe(0);
    expect(summaryResult.stderr).toBe("");
    expect(summary.compat?.removalPendingCount).toBe(9);
    expect(summary.compat?.removalPendingDueCount).toEqual(expect.any(Number));
    expect(summary.compat?.removalPending?.map((record) => record.code)).toEqual([
      "sdk-untrusted-context-identifier-aliases",
      "plugin-sdk-media-understanding-public-demotion",
      "plugin-sdk-memory-host-core-public-demotion",
      "plugin-sdk-channel-lifecycle-subpath",
      "plugin-sdk-channel-message-subpath",
      "plugin-sdk-channel-reply-pipeline-subpath",
      "plugin-sdk-config-runtime-subpath",
      "plugin-sdk-infra-runtime-subpath",
      "plugin-sdk-plugin-config-runtime-public-demotion",
    ]);
    expect(summary.compat?.removalPending?.[0]).toMatchObject({
      removeAfter: "2026-09-08",
      blocker: expect.stringContaining(
        "migration of published plugin readers is verified and explicit breaking-release approval is granted",
      ),
    });
    for (const record of summary.compat?.removalPending ?? []) {
      expect(record.removeAfter).toMatch(/^\d{4}-\d{2}-\d{2}$/u);
      expect(record.blocker).toEqual(expect.stringMatching(/retain|replacement/iu));
      expect(record.readerCount).toEqual(expect.any(Number));
      expect(record.readerSample).toEqual(expect.arrayContaining([expect.any(String)]));
      expect((record.readerSample as unknown[]).length).toBeLessThanOrEqual(5);
      expect(record.dueForReview).toEqual(expect.any(Boolean));
    }
    expect(["private-core-bridge", "private-package-core-integrated"]).toContain(
      summary.memoryHostSdk?.implementation,
    );
  });

  it("treats removeAfter as the final compatibility day", () => {
    expect(
      isPluginCompatEligibleForRemoval("2026-10-01", new Date("2026-10-01T23:59:59.999Z")),
    ).toBe(false);
    expect(
      isPluginCompatEligibleForRemoval("2026-10-01", new Date("2026-10-02T00:00:00.000Z")),
    ).toBe(true);
    expect(isPluginCompatEligibleForRemoval(undefined, new Date("2026-10-02T00:00:00.000Z"))).toBe(
      false,
    );
  });

  it("identifies the failing deprecated records separately from pending removals", () => {
    const fixtureDates = new Map([
      ["media-legacy-projection", "2000-01-01"],
      ["agent-harness-terminal-result-aliases", "2999-01-01"],
      ["plugin-sdk-inbound-reply-dispatch-subpath", undefined],
      ["sdk-untrusted-context-identifier-aliases", "2000-01-01"],
    ]);
    const records = pluginCompatRegistry
      .listPluginCompatRecords()
      .filter((record) => fixtureDates.has(record.code))
      .map((record) => Object.assign({}, record, { removeAfter: fixtureDates.get(record.code) }));
    expect(records).toHaveLength(4);
    const registrySpy = vi.spyOn(pluginCompatRegistry, "listPluginCompatRecords");
    registrySpy.mockReturnValue(records);
    try {
      const args = ["--summary", "--fail-on-eligible-compat"];
      const text = createPluginBoundaryReport(args);
      const json = createPluginBoundaryReport([...args, "--json"]);
      const summary = JSON.parse(json.stdout) as {
        compat: { eligibleForRemoval: unknown[]; removalPendingCount: number };
      };

      expect(text.exitCode).toBe(1);
      expect(text.stderr).toBe(
        "plugin-boundary-report: 1 compatibility record(s) are due for removal\n",
      );
      expect(json.exitCode).toBe(text.exitCode);
      expect(json.stderr).toBe(text.stderr);
      expect(summary.compat.eligibleForRemoval).toEqual([
        { code: "media-legacy-projection", owner: "sdk", removeAfter: "2000-01-01" },
      ]);
      expect(summary.compat.removalPendingCount).toBe(1);
      expect(
        text.stdout.split("\n").filter((line) => line.startsWith("  eligible-for-removal ")),
      ).toEqual(["  eligible-for-removal 2000-01-01 media-legacy-projection owner=sdk"]);
      expect(text.stdout).toContain(
        "  removal-pending 2000-01-01 sdk-untrusted-context-identifier-aliases",
      );
    } finally {
      registrySpy.mockRestore();
    }
  });

  it("renders removal-pending blockers and reader references without changing fail gates", () => {
    const result = createPluginBoundaryReport(["--summary"]);

    expect(result.exitCode).toBe(0);
    expect(result.stderr).toBe("");
    expect(result.stdout).toContain("removalPending=9");
    expect(result.stdout).not.toContain("agent-harness-sdk-alias");
    expect(result.stdout).toMatch(/blocker=.*retain the public/iu);
    expect(result.stdout).toMatch(/readerRefs=\d+ readers=/u);
  });

  it("reports the inbound reply dispatch major-version gate as date-ineligible", () => {
    const jsonResult = createPluginBoundaryReport(["--json", "--owner", "channel"]);
    const report = JSON.parse(jsonResult.stdout) as {
      compat?: {
        records?: Array<{
          code?: unknown;
          removeAfter?: unknown;
          removalGate?: unknown;
          eligibleForRemoval?: unknown;
        }>;
      };
    };
    const record = report.compat?.records?.find(
      (candidate) => candidate.code === "plugin-sdk-inbound-reply-dispatch-subpath",
    );

    expect(jsonResult.exitCode).toBe(0);
    expect(record).toMatchObject({
      removalGate: "next-plugin-sdk-major",
      eligibleForRemoval: false,
    });
    expect(record?.removeAfter).toBeUndefined();

    const textResult = createPluginBoundaryReport(["--owner", "channel"]);
    expect(textResult.stdout).toContain(
      "next-plugin-sdk-major plugin-sdk-inbound-reply-dispatch-subpath",
    );
    expect(textResult.stdout).not.toContain("no-date plugin-sdk-inbound-reply-dispatch-subpath");
  });
});
