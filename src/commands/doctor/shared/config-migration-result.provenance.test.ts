import { describe, expect, it } from "vitest";
import type { ConfigFileSnapshot, OpenClawConfig } from "../../../config/types.openclaw.js";
import {
  prepareDoctorConfigMigrationResult,
  type DoctorConfigPreflightResult,
} from "./config-migration-result.js";

function snapshot(config: OpenClawConfig): ConfigFileSnapshot {
  return {
    path: "/synthetic/openclaw.json",
    exists: true,
    raw: JSON.stringify(config),
    parsed: config,
    sourceConfig: config,
    resolved: config,
    config,
    runtimeConfig: config,
    valid: true,
    issues: [],
    warnings: [],
    legacyIssues: [],
  };
}

function fixture(withProof = true) {
  const config: OpenClawConfig = { gateway: { port: 19091 } };
  const current = snapshot(config);
  const preflight: DoctorConfigPreflightResult = {
    snapshot: current,
    baseConfig: config,
    ...(withProof ? { preflightLegacyStateConfig: config } : {}),
  };
  return { config, finish: prepareDoctorConfigMigrationResult(preflight, current) };
}

function withMetadata<T>(_config: OpenClawConfig, run: () => T): T {
  return run();
}

describe("Doctor preflight legacy-state provenance handoff", () => {
  it("carries proof across an equal config without a write or plugin-generation change", async () => {
    const { config, finish } = fixture();
    const result = await finish({
      cfg: structuredClone(config),
      shouldWriteConfig: false,
      runWithCurrentPluginMetadata: withMetadata,
    });
    expect(result.preflightLegacyStateConfig).toBe(config);
  });

  it("drops proof when the config changes", async () => {
    const { finish } = fixture();
    const result = await finish({
      cfg: { gateway: { port: 19092 } },
      shouldWriteConfig: false,
      runWithCurrentPluginMetadata: withMetadata,
    });
    expect(result).not.toHaveProperty("preflightLegacyStateConfig");
  });

  it.each([
    { label: "config write", shouldWriteConfig: true, pluginInventoryChanged: false },
    { label: "plugin inventory", shouldWriteConfig: false, pluginInventoryChanged: true },
  ])("drops proof for a pending $label even when config bytes are equal", async (changes) => {
    const { config, finish } = fixture();
    const result = await finish({
      cfg: structuredClone(config),
      shouldWriteConfig: changes.shouldWriteConfig,
      pluginInventoryChanged: changes.pluginInventoryChanged,
      runWithCurrentPluginMetadata: withMetadata,
    });
    expect(result).not.toHaveProperty("preflightLegacyStateConfig");
  });

  it("does not manufacture missing preflight proof", async () => {
    const { config, finish } = fixture(false);
    const result = await finish({
      cfg: config,
      shouldWriteConfig: false,
      runWithCurrentPluginMetadata: withMetadata,
    });
    expect(result).not.toHaveProperty("preflightLegacyStateConfig");
  });
});
